package common

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func runResourceCommand(t *testing.T, fc *config.FileConfig, args []string, ) (*bytes.Buffer, error) {
	var stdoutBuff bytes.Buffer
	command := &ResourceCommand{
		stdout: &stdoutBuff,
	}
	cfg := service.MakeDefaultConfig()

	app := utils.InitCLIParser("tctl", GlobalHelpString)
	command.Initialize(app, cfg)

	selectedCmd, err := app.Parse(args)
	require.NoError(t, err)

	var ccf GlobalCLIFlags
	ccf.ConfigString = mustGetBase64EncFileConfig(t, fc)

	clientConfig, err := applyConfig(&ccf, cfg)
	require.NoError(t, err)

	client, err := connectToAuthService(context.Background(), cfg, clientConfig)
	require.NoError(t, err)

	_, err = command.TryRun(selectedCmd, client)
	if err != nil {
		return nil, err
	}
	return &stdoutBuff, nil
}

func mustDecodeJSON(t *testing.T, r io.Reader, i interface{}) {
	err := json.NewDecoder(r).Decode(i)
	require.NoError(t, err)
}

func mustGetFreeLocalListenerAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func mustGetBase64EncFileConfig(t *testing.T, fc *config.FileConfig) string {
	configYamlContent, err := yaml.Marshal(fc)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(configYamlContent)
}

type testServerOptions struct {
	tmpDir     string
	fileConfig *config.FileConfig
}

type testServerOptionFunc func(options *testServerOptions)

func WithFileConfig(fc *config.FileConfig) testServerOptionFunc {
	return func(options *testServerOptions) {
		options.fileConfig = fc
	}
}

func makeAndRunTestAuthServer(t *testing.T, opts ...testServerOptionFunc) (auth *service.TeleportProcess) {
	var options testServerOptions
	for _, opt := range opts {
		opt(&options)
	}

	var err error
	cfg := service.MakeDefaultConfig()
	if options.fileConfig != nil {
		err = config.ApplyFileConfig(options.fileConfig, cfg)
		require.NoError(t, err)
	}

	auth, err = service.NewTeleport(cfg)
	require.NoError(t, err)
	require.NoError(t, auth.Start())

	t.Cleanup(func() {
		auth.Close()
	})

	// Wait for proxy to become ready.
	eventCh := make(chan service.Event, 1)
	auth.WaitForEvent(auth.ExitContext(), service.AuthTLSReady, eventCh)
	select {
	case <-eventCh:
	case <-time.After(30 * time.Second):
		// in reality, the auth server should start *much* sooner than this.  we use a very large
		// timeout here because this isn't the kind of problem that this test is meant to catch.
		t.Fatal("auth server didn't start after 30s")
	}
	return auth
}
