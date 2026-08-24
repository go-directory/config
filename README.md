## config

Package config provides a makeshift `cn=config` abstraction. It is designed for use by [go-directory/dsa](https://github.com/go-directory/dsa) only.

# License

The config package is released under the terms of the MIT license. See the LICENSE file in the [go-directory/dsa](https://github.com/go-directory/dsa) repository root for details.

# Status

This package is currently under heavy development and is considered EXPERIMENTAL. It is not yet intended for use in production environments.

# Example

An instance of `*config.Config` is populated following a call to the `Config.ParseLDIF` or `Config.ReadBytes` methods.

The file specified as the argument to `Config.ParseLDIF` must be a legal LDIF with a root suffix of `cn=config`, and MUST bear a file extension of "`.ldif`". See the `testdata/dse.ldif` for an example.

```go
  c := &Config{}
  err := c.ParseLDIF("/path/to/dse.ldif")
  <check error>
```

... or ...

```go
  c := &Config{}
  err := c.ReadBytes([]byte{<dse LDIF bytes>})
  <check error>
```
