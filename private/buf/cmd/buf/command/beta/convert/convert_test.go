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

package convert

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bufbuild/buf/private/buf/cmd/buf/internal/internaltesting"
	"github.com/bufbuild/buf/private/pkg/app/appcmd"
	"github.com/bufbuild/buf/private/pkg/app/appcmd/appcmdtesting"
	"github.com/bufbuild/buf/private/pkg/app/appflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvert(t *testing.T) {
	t.Run("bin-to-json-file-proto", func(t *testing.T) {
		testConvert(
			t,
			nil,
			"testdata/bin_json/payload.json",
			"testdata/bin_json/payload.bin",
			"--type=buf.Foo",
			"--schema=testdata/bin_json/buf.proto",
		)
	})
	t.Run("json-to-bin-file-proto", func(t *testing.T) {
		testConvert(
			t,
			nil,
			"testdata/bin_json/payload.bin",
			"testdata/bin_json/payload.json",
			"--type=buf.Foo",
			"--schema=testdata/bin_json/buf.proto",
		)
	})
	t.Run("stdin-json-to-bin-proto", func(t *testing.T) {
		testConvert(
			t,
			strings.NewReader(`{"one":"55"}`),
			"testdata/bin_json/payload.bin",
			"--schema=testdata/bin_json/buf.proto",
			"--type=buf.Foo",
			"-#format=json",
		)
	})
	t.Run("stdin-bin-to-json-proto", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/payload.bin")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.json",
			"-#format=bin",
			"--schema=testdata/bin_json/buf.proto",
			"--type=buf.Foo",
		)
	})
	t.Run("stdin-json-to-json-proto", func(t *testing.T) {
		testConvert(
			t,
			strings.NewReader(`{"one":"55"}`),
			"testdata/bin_json/payload.json",
			"--type=buf.Foo",
			"-#format=json",
			"--schema=testdata/bin_json/buf.proto",
			"-o",
			"-#format=json",
		)
	})
	t.Run("stdin-input-to-json-image", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/image.bin")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.json",
			"--type=buf.Foo",
			"testdata/bin_json/payload.bin",
			"--schema=-",
			"-o",
			"-#format=json",
		)
	})
	t.Run("stdin-json-to-json-image", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/payload.bin")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.json",
			"-#format=bin",
			"--type=buf.Foo",
			"--schema=testdata/bin_json/image.bin",
			"-o",
			"-#format=json",
		)
	})
	t.Run("stdin-bin-payload-to-json-with-image", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/payload.bin")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.json",
			"--type=buf.Foo",
			"--schema=testdata/bin_json/image.bin",
			"-o",
			"-#format=json",
		)
	})
	t.Run("stdin-json-payload-to-bin-with-image", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/payload.json")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.bin",
			"-#format=json",
			"--type=buf.Foo",
			"--schema=testdata/bin_json/image.bin",
			"-o",
			"-#format=bin",
		)
	})
	t.Run("stdin-image-json-to-bin", func(t *testing.T) {
		file, err := os.Open("testdata/bin_json/image.json")
		require.NoError(t, err)
		testConvert(
			t,
			file,
			"testdata/bin_json/payload.bin",
			"testdata/bin_json/payload.json",
			"--type=buf.Foo",
			"-o",
			"-#format=bin",
		)
	})

	t.Run("wkt", func(t *testing.T) {
		testConvert(
			t,
			nil,
			"testdata/bin_json/duration.json",
			"testdata/bin_json/duration.bin",
			"--type=google.protobuf.Duration",
			"-o",
			"-#format=json",
		)
	})

}

func testConvert(t *testing.T, stdin io.Reader, want string, args ...string) {
	var stdout bytes.Buffer
	appcmdtesting.RunCommandSuccess(
		t,
		func(name string) *appcmd.Command {
			return NewCommand(
				name,
				appflag.NewBuilder(name),
			)
		},
		internaltesting.NewEnvFunc(t),
		stdin,
		&stdout,
		args...,
	)
	wantReader, err := os.Open(want)
	require.NoError(t, err)
	wantBytes, err := io.ReadAll(wantReader)
	require.NoError(t, err)
	assert.Equal(t, string(wantBytes), stdout.String())
}
