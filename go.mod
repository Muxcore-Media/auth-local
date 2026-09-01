module github.com/Muxcore-Media/auth-local

go 1.26.4

require (
	github.com/Muxcore-Media/core v0.5.8
	github.com/Muxcore-Media/core/pkg/contracts v0.5.8
	github.com/Muxcore-Media/core/sdk/go/module v0.5.8
	github.com/go-webauthn/webauthn v0.17.4
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.54.0
	google.golang.org/grpc v1.82.1
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.53.0
)

require (
	github.com/Muxcore-Media/contracts-media v0.1.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260610212136-7ab31c22f7ad // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/Muxcore-Media/core/pkg/contracts => /home/ender/Projects/MuxCore/core/pkg/contracts

replace github.com/Muxcore-Media/contracts-media => /home/ender/Projects/MuxCore/contracts-media

replace github.com/Muxcore-Media/core => /home/ender/Projects/MuxCore/core

replace github.com/Muxcore-Media/core/sdk/go/module => /home/ender/Projects/MuxCore/core/sdk/go/module

replace github.com/Muxcore-Media/contracts-notification => /home/ender/Projects/MuxCore/contracts-notification

replace github.com/Muxcore-Media/contracts-playback => /home/ender/Projects/MuxCore/contracts-playback

replace github.com/Muxcore-Media/contracts-scanner => /home/ender/Projects/MuxCore/contracts-scanner

replace github.com/Muxcore-Media/contracts-automation => /home/ender/Projects/MuxCore/contracts-automation

replace github.com/Muxcore-Media/contracts-metadata => /home/ender/Projects/MuxCore/contracts-metadata

replace github.com/Muxcore-Media/contracts-media-admin => /home/ender/Projects/MuxCore/contracts-media-admin

replace github.com/Muxcore-Media/contracts-downloader => /home/ender/Projects/MuxCore/contracts-downloader

replace github.com/Muxcore-Media/contracts-indexer => /home/ender/Projects/MuxCore/contracts-indexer

replace github.com/Muxcore-Media/core/pkg/tenant => /home/ender/Projects/MuxCore/core/pkg/tenant

replace github.com/Muxcore-Media/core/sdk/go/client => /home/ender/Projects/MuxCore/core/sdk/go/client
