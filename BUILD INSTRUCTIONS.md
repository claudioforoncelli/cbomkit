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

```bash
docker build -t cbomkit:dev-front -f frontend/docker/Dockerfile .
```

