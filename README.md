
# Install

* install App Engine SDK
* install packages

```
go get -u github.com/dgrijalva/jwt-go
go get -u github.com/gorilla/mux
go get -u google.golang.org/appengine/datastore
go get -u google.golang.org/appengine
go get -u google.golang.org/appengine/log
go get -u github.com/jteeuwen/go-bindata/...
```

# Run development server

```
goapp serve app
```

# Deploy

```
appcfg.py -A <PROJECT_ID> -V v1 update app/
```

# Prepare keys

## Create keys

```
mkdir assets
cd assets
openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-pair.pem
openssl ec -in ec256-key-pair.pem -outform PEM -pubout -out ec256-key-pub.pem
openssl ec -in ec256-key-pair.pem -outform PEM -out ec256-key-pri.pem
```

## Packing keys

```
go-bindata -o bindata/bindata.go assets
```

## Edit bindata.go

* rename package from 'main' to 'bindata'

# Request by curl

## Registration

```
curl -H "Accept: application/json" -H "Content-type: application/json" -X POST -d '{"username":"USERNAME","password":"PASSWORD"}' http://<PROJECT_ID>.appspot.com/registration
```

## Authentication

```
curl -H "Accept: application/json" -H "Content-type: application/json" -X POST -d '{"username":"USERNAME","password":"PASSWORD"}' http://<PROJECT_ID>.appspot.com/authentication
```

## Hello

```
curl -H "Accept: application/json" -H "Content-type: application/json" http://<PROJECT_ID>.appspot.com/hello
```

## Authorized Hello

```
curl -H "Accept: application/json" -H "Content-type: application/json" -H "Authorization: Bearer <TOKEN_STRING_RETURNED_WHEN_AUTHENTICATION>" http://<PROJECT_ID>.appspot.com/authorized_hello
```