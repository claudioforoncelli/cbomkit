# Build Instructions

## 1. Run Maven Build

```bash
mvn clean package
```

## 2. Build Backend

```bash
docker build -t cbomkit:dev-back -f src/main/docker/Dockerfile.jvm .
```

## 3. Build Frontend

In /frontend folder
```bash
npm install && npm run build
```

In main folder
```bash
docker build -t cbomkit:dev-front -f frontend/docker/Dockerfile .
```

## 4. Execute
```bash
make production
```

CBOMkit will be available at 
`
http://localhost:8000/
`

