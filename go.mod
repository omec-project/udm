module github.com/free5gc/udm

go 1.14

require (
	github.com/antihax/optional v1.0.0
	github.com/antonfisher/nested-logrus-formatter v1.3.0
	github.com/free5gc/UeauCommon v1.0.0
	github.com/free5gc/http2_util v1.0.0
	github.com/free5gc/http_wrapper v1.0.0
	github.com/free5gc/idgenerator v1.0.0
	github.com/free5gc/logger_conf v1.0.0
	github.com/free5gc/logger_util v1.0.0
	github.com/free5gc/milenage v1.0.0
	github.com/free5gc/openapi v1.0.0
	github.com/free5gc/path_util v1.0.0
	github.com/free5gc/util_3gpp v1.0.0
	github.com/free5gc/version v1.0.0
	github.com/gin-gonic/gin v1.6.3
	github.com/google/uuid v1.1.2
	github.com/omec-project/udm v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.7.0
	github.com/urfave/cli v1.22.5
	google.golang.org/grpc v1.32.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/omec-project/udm => ../udm
