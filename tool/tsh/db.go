/*
Copyright 2020-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/teleport/api/v7/client/proto"
	"github.com/gravitational/teleport/api/v7/types"
	"github.com/gravitational/teleport/lib/client"
	dbprofile "github.com/gravitational/teleport/lib/client/db"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// onListDatabases implements "tsh db ls" command.
func onListDatabases(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	var servers []types.DatabaseServer
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServers(cf.Context)
		return trace.Wrap(err)
	})
	if err != nil {
		return trace.Wrap(err)
	}
	// Refresh the creds in case user was logged into any databases.
	err = fetchDatabaseCreds(cf, tc)
	if err != nil {
		return trace.Wrap(err)
	}
	// Retrieve profile to be able to show which databases user is logged into.
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].GetName() < servers[j].GetName()
	})
	showDatabases(tc.SiteName, types.DeduplicateDatabaseServers(servers),
		profile.Databases, cf.Verbose)
	return nil
}

// onDatabaseLogin implements "tsh db login" command.
func onDatabaseLogin(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	var servers []types.DatabaseServer
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		allServers, err := tc.ListDatabaseServers(cf.Context)
		for _, server := range allServers {
			if server.GetName() == cf.DatabaseService {
				servers = append(servers, server)
			}
		}
		return trace.Wrap(err)
	})
	if err != nil {
		return trace.Wrap(err)
	}
	if len(servers) == 0 {
		return trace.NotFound(
			"database %q not found, use 'tsh db ls' to see registered databases", cf.DatabaseService)
	}
	err = databaseLogin(cf, tc, tlsca.RouteToDatabase{
		ServiceName: cf.DatabaseService,
		Protocol:    servers[0].GetProtocol(),
		Username:    cf.DatabaseUser,
		Database:    cf.DatabaseName,
	}, false)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func databaseLogin(cf *CLIConf, tc *client.TeleportClient, db tlsca.RouteToDatabase, quiet bool) error {
	log.Debugf("Fetching database access certificate for %s on cluster %v.", db, tc.SiteName)
	// When generating certificate for MongoDB access, database username must
	// be encoded into it. This is required to be able to tell which database
	// user to authenticate the connection as.
	if db.Protocol == defaults.ProtocolMongoDB && db.Username == "" {
		return trace.BadParameter("please provide the database user name using --db-user flag")
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	err = tc.ReissueUserCerts(cf.Context, client.CertCacheKeep, client.ReissueParams{
		RouteToCluster: tc.SiteName,
		RouteToDatabase: proto.RouteToDatabase{
			ServiceName: db.ServiceName,
			Protocol:    db.Protocol,
			Username:    db.Username,
			Database:    db.Database,
		},
		AccessRequests: profile.ActiveRequests.AccessRequests,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	// Refresh the profile.
	profile, err = client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	// Update the database-specific connection profile file.
	err = dbprofile.Add(tc, db, *profile)
	if err != nil {
		return trace.Wrap(err)
	}
	// Print after-connect message.
	if !quiet {
		return connectMessage.Execute(os.Stdout, db)
	}
	return nil
}

// fetchDatabaseCreds is called as a part of tsh login to refresh database
// access certificates for databases the current profile is logged into.
func fetchDatabaseCreds(cf *CLIConf, tc *client.TeleportClient) error {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	if trace.IsNotFound(err) {
		return nil // No currently logged in profiles.
	}
	for _, db := range profile.Databases {
		if err := databaseLogin(cf, tc, db, true); err != nil {
			log.WithError(err).Errorf("Failed to fetch database access certificate for %s.", db)
			if err := databaseLogout(tc, db); err != nil {
				log.WithError(err).Errorf("Failed to log out of database %s.", db)
			}
		}
	}
	return nil
}

// onDatabaseLogout implements "tsh db logout" command.
func onDatabaseLogout(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	var logout []tlsca.RouteToDatabase
	// If database name wasn't given on the command line, log out of all.
	if cf.DatabaseService == "" {
		logout = profile.Databases
	} else {
		for _, db := range profile.Databases {
			if db.ServiceName == cf.DatabaseService {
				logout = append(logout, db)
			}
		}
		if len(logout) == 0 {
			return trace.BadParameter("Not logged into database %q",
				tc.DatabaseService)
		}
	}
	for _, db := range logout {
		if err := databaseLogout(tc, db); err != nil {
			return trace.Wrap(err)
		}
	}
	if len(logout) == 1 {
		fmt.Println("Logged out of database", logout[0].ServiceName)
	} else {
		fmt.Println("Logged out of all databases")
	}
	return nil
}

func databaseLogout(tc *client.TeleportClient, db tlsca.RouteToDatabase) error {
	// First remove respective connection profile.
	err := dbprofile.Delete(tc, db)
	if err != nil {
		return trace.Wrap(err)
	}
	// Then remove the certificate from the keystore.
	err = tc.LogoutDatabase(db.ServiceName)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// onDatabaseEnv implements "tsh db env" command.
func onDatabaseEnv(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	env, err := dbprofile.Env(tc, *database)
	if err != nil {
		return trace.Wrap(err)
	}
	for k, v := range env {
		fmt.Printf("export %v=%v\n", k, v)
	}
	return nil
}

// onDatabaseConfig implements "tsh db config" command.
func onDatabaseConfig(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	// Postgres proxy listens on web proxy port while MySQL proxy listens on
	// a separate port due to the specifics of the protocol.
	var host string
	var port int
	switch database.Protocol {
	case defaults.ProtocolPostgres:
		host, port = tc.PostgresProxyHostPort()
	case defaults.ProtocolMySQL:
		host, port = tc.MySQLProxyHostPort()
	case defaults.ProtocolMongoDB:
		host, port = tc.WebProxyHostPort()
	default:
		return trace.BadParameter("unknown database protocol: %q", database)
	}
	switch cf.Format {
	case dbFormatCommand:
		cmd, err := getConnectCommand(cf, tc, profile, database)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Println(cmd.Path, strings.Join(cmd.Args[1:], " "))
	default:
		fmt.Printf(`Name:      %v
Host:      %v
Port:      %v
User:      %v
Database:  %v
CA:        %v
Cert:      %v
Key:       %v
`,
			database.ServiceName, host, port, database.Username,
			database.Database, profile.CACertPath(),
			profile.DatabaseCertPath(database.ServiceName), profile.KeyPath())
	}
	return nil
}

// onDatabaseConnect implements "tsh db connect" command.
func onDatabaseConnect(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	cmd, err := getConnectCommand(cf, tc, profile, database)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Debugf("Executing command: %s.", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// pickActiveDatabase returns the database the current profile is logged into.
//
// If logged into multiple databases, returns an error unless one specified
// explicily via --db flag.
func pickActiveDatabase(cf *CLIConf) (*tlsca.RouteToDatabase, error) {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(profile.Databases) == 0 {
		return nil, trace.NotFound("Please login using 'tsh db login' first")
	}
	name := cf.DatabaseService
	if name == "" {
		services := profile.DatabaseServices()
		if len(services) > 1 {
			return nil, trace.BadParameter("Multiple databases are available (%v), please specify one using CLI argument",
				strings.Join(services, ", "))
		}
		name = services[0]
	}
	for _, db := range profile.Databases {
		if db.ServiceName == name {
			return &db, nil
		}
	}
	return nil, trace.NotFound("Not logged into database %q", name)
}

func getConnectCommand(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, db *tlsca.RouteToDatabase) (*exec.Cmd, error) {
	switch db.Protocol {
	case defaults.ProtocolPostgres:
		return getPostgresCommand(db, profile.Cluster, cf.DatabaseUser, cf.DatabaseName), nil
	case defaults.ProtocolMySQL:
		return getMySQLCommand(db, profile.Cluster, cf.DatabaseUser, cf.DatabaseName), nil
	case defaults.ProtocolMongoDB:
		host, port := tc.WebProxyHostPort()
		return getMongoCommand(host, port, profile.DatabaseCertPath(db.ServiceName), cf.DatabaseName), nil
	}
	return nil, trace.BadParameter("unsupported database protocol: %v", db)
}

func getPostgresCommand(db *tlsca.RouteToDatabase, cluster, user, name string) *exec.Cmd {
	connString := []string{fmt.Sprintf("service=%v-%v", cluster, db.ServiceName)}
	if user != "" {
		connString = append(connString, fmt.Sprintf("user=%v", user))
	}
	if name != "" {
		connString = append(connString, fmt.Sprintf("dbname=%v", name))
	}
	return exec.Command(postgresBin, strings.Join(connString, " "))
}

func getMySQLCommand(db *tlsca.RouteToDatabase, cluster, user, name string) *exec.Cmd {
	args := []string{fmt.Sprintf("--defaults-group-suffix=_%v-%v", cluster, db.ServiceName)}
	if user != "" {
		args = append(args, "--user", user)
	}
	if name != "" {
		args = append(args, "--database", name)
	}
	return exec.Command(mysqlBin, args...)
}

func getMongoCommand(host string, port int, certPath, name string) *exec.Cmd {
	args := []string{"--host", host, "--port", strconv.Itoa(port), "--ssl", "--sslPEMKeyFile", certPath}
	if name != "" {
		args = append(args, name)
	}
	return exec.Command(mongoBin, args...)
}

const (
	// dbFormatText prints database configuration in text format.
	dbFormatText = "text"
	// dbFormatCommand prints database connection command.
	dbFormatCommand = "cmd"
)

const (
	// postgresBin is the Postgres client binary name.
	postgresBin = "psql"
	// mysqlBin is the MySQL client binary name.
	mysqlBin = "mysql"
	// mongoBin is the Mongo client binary name.
	mongoBin = "mongo"
)

// connectMessage is printed after successful login to a database.
var connectMessage = template.Must(template.New("").Parse(fmt.Sprintf(`
Connection information for database "{{.ServiceName}}" has been saved.

You can now connect to it using the following command:

  %v

Or view the connect command for the native database CLI client:

  %v

`,
	utils.Color(utils.Yellow, "tsh db connect {{.ServiceName}}"),
	utils.Color(utils.Yellow, "tsh db config --format=cmd {{.ServiceName}}"))))
