package common

import (
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

// TestDatabaseResource tests tctl db rm/get commands.
func TestDatabaseResource(t *testing.T) {
	const (
		deadline   = time.Second * 2
		retryDelay = time.Millisecond * 100
	)

	fileConfig := &config.FileConfig{
		Databases: config.Databases{
			Service: config.Service{
				EnabledFlag: "true",
			},
			Databases: []*config.Database{
				{
					Name:        "example",
					Description: "Example MySQL",
					Protocol:    "mysql",
					URI:         "localhost:33306",
				},
				{
					Name:        "example2",
					Description: "Example2 MySQL",
					Protocol:    "mysql",
					URI:         "localhost:33307",
				},
			},
		},
		Proxy: config.Proxy{
			Service: config.Service{
				EnabledFlag: "true",
			},
		},
		Auth: config.Auth{
			Service: config.Service{
				EnabledFlag:   "true",
				ListenAddress: mustGetFreeLocalListenerAddr(),
			},
		},
	}

	makeAndRunTestAuthServer(t, WithFileConfig(fileConfig))

	var out []*types.DatabaseServerV3

	t.Run("get all databases", func(t *testing.T) {
		// Retry to fetch  DB resource and wait for cache propagation.
		err := utils.RetryStaticFor(deadline, retryDelay, func() error {
			buff, err := runResourceCommand(t, fileConfig, []string{"get", "db", "--format=json"})
			require.NoError(t, err)

			mustDecodeJSON(t, buff, &out)
			if got, want := len(out), 2; got != want {
				return trace.NotFound("resource length mismatch got=%v, want=%v", got, want)
			}
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("get example database", func(t *testing.T) {
		buff, err := runResourceCommand(t, fileConfig, []string{"get", "db/example", "--format=json"})
		require.NoError(t, err)

		mustDecodeJSON(t, buff, &out)
		require.Len(t, out, 1)
	})

	t.Run("remove example2 database", func(t *testing.T) {
		_, err := runResourceCommand(t, fileConfig, []string{"rm", "db/example2"})
		require.NoError(t, err)

		// Retry to fetch DB resource and wait for cache propagation.
		utils.RetryStaticFor(deadline, retryDelay, func() error {
			// Fetching removed db resource should return NotFound error
			_, err = runResourceCommand(t, fileConfig, []string{"get", "db/example2", "--format=json"})
			if !trace.IsNotFound(err) {
				return trace.BadParameter("invalid error %v", err)
			}

			buff, err := runResourceCommand(t, fileConfig, []string{"get", "db", "--format=json"})
			require.NoError(t, err)
			mustDecodeJSON(t, buff, &out)
			if got, want := len(out), 1; got != want {
				return trace.NotFound("resource length mismatch got=%v, want=%v", got, want)
			}
			return nil
		})
	})
}
