Authentication process with jwt in speign boot. Backend only!

Start server: .\mvnw clean spring-boot:run

## Endpoints
### Register with body:
```
http://localhost:8080/api/v1/auth/register
{
    "firstname": "Max",
    "lastname": "Mustermann",
    "email": "max-mustermann@mail.com",
    "password": "123456"
}
```

### Authentication and try out with Bearer Token:
```
http://localhost:8080/api/v1/auth/authenticate
http://localhost:8080/api/v1/demo-controller
```
