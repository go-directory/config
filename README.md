## config

Package config provides a makeshift `cn=config` abstraction. It is designed specifically for use by the [Go Directory Project](https://github.com/go-directory).

The package operates by parsing LDIF content, typically read from disk. Once parsed and deemed valid, the data is marshaled via reflection into an instance of `*config.Config`. This object, in turn, can be interrogated by upstream consuming packages such as [go-directory/dsa](https://github.com/go-directory/dsa) and [go-directory/dib](https://github.com/go-directory/dib) for the purpose of centralized runtime configuration.

# License

The config package is released under the terms of the MIT license. See the LICENSE file in the [go-directory/dsa](https://github.com/go-directory/dsa) repository root for details.

# Status

This package is currently under heavy development and is prone to breaking changes. It is not yet intended for use in any production environment.

# Example

An instance of `*config.Config` is populated following a call to the `Config.ParseLDIF` or `Config.ReadBytes` methods.

The file specified as the argument to `Config.ParseLDIF` must be a legal LDIF with a root suffix of `cn=config`, and MUST bear a file extension of "`.ldif`". See the `testdata/dse.ldif` for an example.

```go
  c := &Config{}
  err := c.ParseLDIF("/path/to/dse.ldif")
  <check error>
```

... or, if you already have the file bytes ...

```go
  c := &Config{}
  err := c.ReadBytes([]byte{<dse LDIF bytes>})
  <check error>
```
