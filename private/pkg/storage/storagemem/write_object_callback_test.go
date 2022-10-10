// Copyright 2020-2022 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storagemem_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bufbuild/buf/private/pkg/storage/storagemem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCallbackIsInvoked(t *testing.T) {
	t.Parallel()
	var (
		wg          sync.WaitGroup
		invocations int
	)
	const (
		filePathToWrite   = "my/path/to/file.foo"
		dataPrefixToWrite = "some data to write:"
	)
	callbackFn := func(objectPath string, data []byte) {
		assert.Equal(t, filePathToWrite, objectPath)
		assert.True(t, strings.HasPrefix(string(data), dataPrefixToWrite), fmt.Sprintf("written data %q is not prefixed by %q", string(data), dataPrefixToWrite))
		invocations++
		wg.Done()
	}
	rwb := storagemem.NewReadWriteBucket(
		storagemem.ReadWriteBucketWithWriteObjectCallback(callbackFn),
	)
	woc, err := rwb.Put(context.Background(), filePathToWrite)
	require.NoError(t, err)
	const writesToPerform = 5
	for i := 0; i < writesToPerform; i++ {
		wg.Add(1)
		_, err = woc.Write([]byte(dataPrefixToWrite + strconv.Itoa(i)))
		require.NoError(t, err)
	}
	wg.Wait()
	assert.Equal(t, writesToPerform, invocations)
}

func TestWriteWorksIfNoCallbackIsPassed(t *testing.T) {
	t.Parallel()
	const filePathToWrite = "my/path/to/file.foo"
	rwb := storagemem.NewReadWriteBucket() // no callbackfn
	woc, err := rwb.Put(context.Background(), filePathToWrite)
	require.NoError(t, err)
	_, err = woc.Write([]byte("some data to write"))
	require.NoError(t, err)
}
