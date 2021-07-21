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

package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
)

func TestProxyWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	type client struct {
		services.Presence
		types.Events
	}

	presence := local.NewPresenceService(bk)
	w, err := services.NewProxyWatcher(ctx, services.ProxyWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:   "test",
			RetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Presence: presence,
				Events:   local.NewEventsService(bk, nil),
			},
		},
		ProxiesC: make(chan []types.Server, 10),
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	// Since no proxy is yet present, the ProxyWatcher should immediately
	// yield back to its retry loop.
	select {
	case <-w.ResetC:
	case <-time.After(time.Second):
		t.Fatalf("Timeout waiting for ProxyWatcher reset.")
	}

	// Add a proxy server.
	proxy := newProxyServer(t, "proxy1", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy))

	// The first event is always the current list of proxies.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the first event.")
	}

	// Add a second proxy.
	proxy2 := newProxyServer(t, "proxy2", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy2))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 2)
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}

	// Delete the first proxy.
	require.NoError(t, presence.DeleteProxy(proxy.GetName()))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy2))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
}

func newProxyServer(t *testing.T, name, addr string) types.Server {
	s, err := types.NewServer(name, types.KindProxy, types.ServerSpecV2{
		Addr:       addr,
		PublicAddr: addr,
	})
	require.NoError(t, err)
	return s
}

func TestLockWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            clock,
	})
	require.NoError(t, err)

	type client struct {
		services.Access
		types.Events
	}

	access := local.NewAccessService(bk)
	w, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:   "test",
			RetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Access: access,
				Events: local.NewEventsService(bk, nil),
			},
			Clock: clock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	// Subscribe to lock watcher updates.
	target := types.LockTarget{Node: "node"}
	require.Nil(t, w.GetSomeLockInForce(target))
	sub, err := w.Subscribe(ctx, target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sub.Close()) })

	// Add an *expired* lock matching the subscription target.
	pastTime := clock.Now().Add(-time.Minute)
	lock, err := types.NewLock("lock", types.LockSpecV2{
		Target:  target,
		Expires: &pastTime,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
	}
	require.Nil(t, w.GetSomeLockInForce(target))

	// Update the lock so it becomes in force.
	futureTime := clock.Now().Add(time.Minute)
	lock.SetLockExpiry(&futureTime)
	require.NoError(t, access.UpsertLock(ctx, lock))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpPut, event.Type)
		receivedLock, ok := event.Resource.(types.Lock)
		require.True(t, ok)
		require.Empty(t, resourceDiff(receivedLock, lock))
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
	require.Empty(t, resourceDiff(w.GetSomeLockInForce(target), lock))

	// Delete the lock.
	require.NoError(t, access.DeleteLock(ctx, lock.GetName()))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpDelete, event.Type)
		require.Equal(t, event.Resource.GetName(), lock.GetName())
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
	require.Nil(t, w.GetSomeLockInForce(target))

	// Add a lock matching a different target.
	target2 := types.LockTarget{User: "user"}
	require.Nil(t, w.GetSomeLockInForce(target2))
	lock2, err := types.NewLock("lock2", types.LockSpecV2{
		Target: target2,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock2))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
	}
	require.Nil(t, w.GetSomeLockInForce(target))
	require.Empty(t, resourceDiff(w.GetSomeLockInForce(target2), lock2))
}

func resourceDiff(res1, res2 types.Resource) string {
	return cmp.Diff(res1, res2,
		cmpopts.IgnoreFields(types.Metadata{}, "ID"),
		cmpopts.EquateEmpty())
}
