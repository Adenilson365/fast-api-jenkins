# fast-api-jenkins

API mínima para praticar pipelines multibranch e deploy com Jenkins.

Para executar localmente:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

A rota `GET /` retorna `{"message": "Olá, Jenkins!"}`. A documentação
interativa fica em `http://127.0.0.1:8000/docs`.

Para criar a imagem:

```bash
docker build -t fast-api-jenkins:latest .
```

Os manifests estão em `k8s/`. Antes do deploy, ajuste a imagem no
`deployment.yaml` para uma imagem publicada no seu registry ou carregada
no cluster. Para usar uma imagem local com a tag `latest`, configure
`imagePullPolicy: IfNotPresent` no container.

O Ingress usa o host `fast-api.local` e depende de um Ingress Controller
no cluster. Ajuste o host e, se necessário, `spec.ingressClassName` conforme
seu ambiente e configure a resolução do host para o endereço do controller.

```bash
kubectl apply -f k8s/
```
