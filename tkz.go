package config

/*
DN tokens
*/
var (
	cnConfigDN         = []byte(`cn=config`)
	cnControlsConfigDN = []byte(`cn=controls,cn=config`)
	cnDIBConfigDN      = []byte(`cn=dib,cn=config`)
	cnExOpConfigDN     = []byte(`cn=exop,cn=config`)
	cnFeaturesConfigDN = []byte(`cn=features,cn=config`)
	cnIndicesConfigDN  = []byte(`cn=indices,cn=config`)
	cnLimitsConfigDN   = []byte(`cn=limits,cn=config`)
	cnSchemataConfigDN = []byte(`cn=schemata,cn=config`)
	cnTLSConfigDN      = []byte(`cn=tls,cn=config`)
)

/*
RDN (leaf) tokens
*/
var (
	dibRDN      = []byte("cn=dib")
	chainingRDN = []byte("cn=chaining")
	limitsRDN   = []byte("cn=limits")
	indexRDN    = []byte("cn=index")
	indicesRDN  = []byte("cn=indices")
	tlsRDN      = []byte("cn=tls")
	syncRDN     = []byte("cn=sync")
	
)

/*
class tokens
*/
var (
	ocConfig     = []byte("goDirConfig")
	ocDIB        = []byte("goDirConfigDIB")
	ocDIT        = []byte("goDirConfigDIT")
	ocChain      = []byte("goDirConfigChain")
	ocChains     = []byte("goDirConfigChains")
	ocControl    = []byte("goDirConfigControl")
	ocControls   = []byte("goDirConfigControls")
	ocExtention  = []byte("goDirConfigExtension")
	ocExtentions = []byte("goDirConfigExtensions")
	ocFeature    = []byte("goDirConfigFeature")
	ocFeatures   = []byte("goDirConfigFeatures")
	ocIndex      = []byte("goDirConfigIndex")
	ocIndices    = []byte("goDirConfigIndices")
	ocReplAgmt   = []byte("goDirConfigReplAgreement")	
	ocSchema     = []byte("goDirConfigSchema")
	ocSchemata   = []byte("goDirConfigSchemata")
	ocTLS        = []byte("goDirConfigTLS")
)

/*
attributeDescription tokens
*/
var (
	adOC     = ad("objectClass")
	adCN     = ad("cn")
	adDesc   = ad(`description`)
	adSLimit = ad("configSizeLimit")
	adTLimit = ad("configTimeLimit")
	adLCert  = ad(`configTLSListenerCert`)
	adLKey   = ad(`configTLSListenerKey`)
	adCCert  = ad(`configTLSClientCert`)
	adCKey   = ad(`configTLSClientKey`)
	adCA     = ad(`configTLSCA`)
	adMutual = ad(`configTLSClientMutual`)
)

/*
misc. tokens
*/
var (
	comma = []byte(`,`)
	bTrue = []byte("TRUE")
)

func commaAppend(value []byte) []byte  { return append(value, comma...) }
func commaPrepend(value []byte) []byte { return append(comma, value...) }
func joinDNComps(leaf, suffix []byte) []byte {
        leaf = append(leaf, comma...)
        return append(leaf, suffix...)
}
