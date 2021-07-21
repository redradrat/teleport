/*
Copyright 2021 Gravitational, Inc.

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

package db

import (
	"context"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/v7/types"
	"github.com/gravitational/teleport/api/v7/types/events"
	libevents "github.com/gravitational/teleport/lib/events"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// TestAuditPostgres verifies proper audit events are emitted for Postgres
// connections.
func TestAuditPostgres(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedPostgres("postgres"))
	go testCtx.startHandlingConnections()

	testCtx.createUserAndRole(ctx, t, "alice", "admin", []string{"postgres"}, []string{"postgres"})

	// Access denied should trigger an unsuccessful session start event.
	_, err := testCtx.postgresClient(ctx, "alice", "postgres", "notpostgres", "notpostgres")
	require.Error(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionStartFailureCode)

	// Connect should trigger successful session start event.
	psql, err := testCtx.postgresClient(ctx, "alice", "postgres", "postgres", "postgres")
	require.NoError(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionStartCode)

	// Simple query should trigger the query event.
	_, err = psql.Exec(ctx, "select 1").ReadAll()
	require.NoError(t, err)
	requireQueryEvent(t, testCtx, libevents.DatabaseSessionQueryCode, "select 1")

	// Prepared statement execution should also trigger a query event.
	result := psql.ExecParams(ctx, "select now()", nil, nil, nil, nil).Read()
	require.NoError(t, result.Err)
	requireQueryEvent(t, testCtx, libevents.DatabaseSessionQueryCode, "select now()")

	// Closing connection should trigger session end event.
	err = psql.Close(ctx)
	require.NoError(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionEndCode)
}

// TestAuditMySQL verifies proper audit events are emitted for MySQL
// connections.
func TestAuditMySQL(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedMySQL("mysql"))
	go testCtx.startHandlingConnections()

	testCtx.createUserAndRole(ctx, t, "alice", "admin", []string{"root"}, []string{types.Wildcard})

	// Access denied should trigger an unsuccessful session start event.
	_, err := testCtx.mysqlClient("alice", "mysql", "notroot")
	require.Error(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionStartFailureCode)

	// Connect should trigger successful session start event.
	mysql, err := testCtx.mysqlClient("alice", "mysql", "root")
	require.NoError(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionStartCode)

	// Simple query should trigger the query event.
	_, err = mysql.Execute("select 1")
	require.NoError(t, err)
	requireQueryEvent(t, testCtx, libevents.DatabaseSessionQueryCode, "select 1")

	// Closing connection should trigger session end event.
	err = mysql.Close()
	require.NoError(t, err)
	requireEvent(t, testCtx, libevents.DatabaseSessionEndCode)
}

// TestAuditMongo verifies proper audit events are emitted for MongoDB
// connections.
func TestAuditMongo(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedMongo("mongo"))
	go testCtx.startHandlingConnections()

	testCtx.createUserAndRole(ctx, t, "alice", "admin", []string{"admin"}, []string{"admin"})

	// Access denied should trigger an unsuccessful session start event.
	_, err := testCtx.mongoClient(ctx, "alice", "mongo", "notadmin")
	require.Error(t, err)
	waitForEvent(t, testCtx, libevents.DatabaseSessionStartFailureCode)

	// Connect should trigger successful session start event.
	mongo, err := testCtx.mongoClient(ctx, "alice", "mongo", "admin")
	require.NoError(t, err)
	waitForEvent(t, testCtx, libevents.DatabaseSessionStartCode)

	// Find command in a database we don't have access to.
	_, err = mongo.Database("notadmin").Collection("test").Find(ctx, bson.M{})
	require.Error(t, err)
	waitForEvent(t, testCtx, libevents.DatabaseSessionQueryFailedCode)

	// Find command should trigger the query event.
	_, err = mongo.Database("admin").Collection("test").Find(ctx, bson.M{})
	require.NoError(t, err)
	waitForEvent(t, testCtx, libevents.DatabaseSessionQueryCode)

	// Closing connection should trigger session end event.
	err = mongo.Disconnect(ctx)
	require.NoError(t, err)
	waitForEvent(t, testCtx, libevents.DatabaseSessionEndCode)
}

func requireEvent(t *testing.T, testCtx *testContext, code string) {
	event := waitForAnyEvent(t, testCtx)
	require.Equal(t, code, event.GetCode())
}

func requireQueryEvent(t *testing.T, testCtx *testContext, code, query string) {
	event := waitForAnyEvent(t, testCtx)
	require.Equal(t, code, event.GetCode())
	require.Equal(t, query, event.(*events.DatabaseSessionQuery).DatabaseQuery)
}

func waitForAnyEvent(t *testing.T, testCtx *testContext) events.AuditEvent {
	select {
	case event := <-testCtx.emitter.eventsCh:
		return event
	case <-time.After(time.Second):
		t.Fatalf("didn't receive any event after 1 second")
	}
	return nil
}

// waitForEvent waits for particular event code ignoring other events.
func waitForEvent(t *testing.T, testCtx *testContext, code string) events.AuditEvent {
	for {
		select {
		case event := <-testCtx.emitter.eventsCh:
			if event.GetCode() != code {
				continue
			}
			return event
		case <-time.After(time.Second):
			t.Fatalf("didn't receive %v event after 1 second", code)
		}
	}
}

// testEmitter pushes all received audit events into a channel.
type testEmitter struct {
	eventsCh chan events.AuditEvent
	log      logrus.FieldLogger
}

// newTestEmitter returns a new instance of test emitter.
func newTestEmitter() *testEmitter {
	return &testEmitter{
		eventsCh: make(chan events.AuditEvent, 100),
		log:      logrus.WithField(trace.Component, "emitter"),
	}
}

// EmitAuditEvent records the provided event in the test emitter.
func (e *testEmitter) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	e.log.Infof("EmitAuditEvent(%v)", event)
	e.eventsCh <- event
	return nil
}
