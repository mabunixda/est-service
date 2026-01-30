# Kubernetes Deployment Guide

Complete Kubernetes manifests for deploying EST Service.

## Prerequisites

- Kubernetes 1.24+
- kubectl configured
- OpenBao or Vault instance (can be in-cluster or external)
- TLS certificates
- (Optional) cert-manager for automated certificate management
- (Optional) Prometheus Operator for monitoring

## Quick Start

### 1. Create namespace

```bash
# Create the namespace (typically done by cluster admin)
kubectl create namespace est-service
```

### 2. Create secrets

Generate TLS certificates:
```bash
# Generate server certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=est.example.com"

# Create TLS secret
kubectl create secret tls est-service-tls \
  --cert=server.crt --key=server.key \
  -n est-service

# Create CA secret (if using client cert auth)
kubectl create secret generic est-service-ca \
  --from-file=ca.crt=client-ca.crt \
  -n est-service

# Create OpenBao token secret
kubectl create secret generic openbao-token \
  --from-literal=token=<your-token> \
  -n est-service
```

### 3. Deploy configuration

```bash
kubectl apply -f configmap.yaml
kubectl apply -f rbac.yaml
```

### 4. Deploy application

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

### 5. Configure ingress (optional)

Edit `ingress.yaml` with your domain, then:
```bash
kubectl apply -f ingress.yaml
```

### 6. Enable autoscaling (optional)

```bash
kubectl apply -f autoscaling.yaml
```

### 7. Setup monitoring (optional)

If using Prometheus Operator:
```bash
kubectl apply -f servicemonitor.yaml
```

## Verification

Check deployment status:
```bash
kubectl get pods -n est-service
kubectl get svc -n est-service
kubectl logs -n est-service -l app=est-service
```

Test health endpoint:
```bash
kubectl port-forward -n est-service svc/est-service 8443:8443
curl -k https://localhost:8443/health
```

Test metrics:
```bash
kubectl port-forward -n est-service svc/est-service 9090:9090
curl http://localhost:9090/metrics
```

## Configuration

### ConfigMap

Edit `configmap.yaml` to customize:
- Backend connection (OpenBao/Vault address)
- EST policies and labels
- Rate limiting settings
- Log level

Apply changes:
```bash
kubectl apply -f configmap.yaml
kubectl rollout restart deployment/est-service -n est-service
```

### Secrets

Update secrets:
```bash
# Update TLS certificate
kubectl create secret tls est-service-tls \
  --cert=new-server.crt --key=new-server.key \
  -n est-service --dry-run=client -o yaml | kubectl apply -f -

# Update OpenBao token
kubectl create secret generic openbao-token \
  --from-literal=token=<new-token> \
  -n est-service --dry-run=client -o yaml | kubectl apply -f -

# Restart pods to pick up new secrets
kubectl rollout restart deployment/est-service -n est-service
```

## Scaling

### Manual scaling

```bash
kubectl scale deployment/est-service --replicas=5 -n est-service
```

### Horizontal Pod Autoscaler

The HPA automatically scales based on CPU/memory:
- Min replicas: 2
- Max replicas: 10
- Target CPU: 70%
- Target Memory: 80%

Monitor autoscaling:
```bash
kubectl get hpa -n est-service
kubectl describe hpa est-service -n est-service
```

### Pod Disruption Budget

PDB ensures at least 1 pod is always available during disruptions:
```bash
kubectl get pdb -n est-service
```

## Monitoring

### Prometheus Integration

ServiceMonitor configuration for Prometheus Operator:
- Scrape interval: 30s
- Metrics endpoint: `:9090/metrics`

View metrics in Prometheus:
```bash
# Forward Prometheus port
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Query metrics
curl 'http://localhost:9090/api/v1/query?query=est_requests_total'
```

### Grafana Dashboards

Import the EST Service dashboard:
1. Open Grafana
2. Import dashboard from JSON
3. Use `deployments/grafana/dashboards/est-service.json`

## Security

### Network Policies

Apply network policies to restrict traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: est-service
  namespace: est-service
spec:
  podSelector:
    matchLabels:
      app: est-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 8443
    - protocol: TCP
      port: 9090
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: openbao
    ports:
    - protocol: TCP
      port: 8200
  - to:  # DNS
    ports:
    - protocol: UDP
      port: 53
```

### Pod Security

The deployment enforces:
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- Drop all capabilities
- Seccomp profile: RuntimeDefault

### RBAC

Minimal permissions granted:
- Read secrets (TLS certificates, tokens)
- Read configmaps (configuration)

## Troubleshooting

### Pod not starting

```bash
kubectl describe pod -n est-service -l app=est-service
kubectl logs -n est-service -l app=est-service --previous
```

Common issues:
- Missing secrets
- Invalid configuration
- Backend unreachable

### Backend connection errors

Check backend connectivity:
```bash
kubectl run -it --rm debug --image=alpine --restart=Never -n est-service -- sh
# Inside pod:
apk add curl
curl http://openbao.openbao.svc.cluster.local:8200/v1/sys/health
```

### Certificate issues

Verify TLS secrets:
```bash
kubectl get secret est-service-tls -n est-service -o yaml
kubectl get secret est-service-ca -n est-service -o yaml
```

Test certificate:
```bash
kubectl get secret est-service-tls -n est-service -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

### Performance issues

Check resource usage:
```bash
kubectl top pods -n est-service
kubectl describe hpa est-service -n est-service
```

Increase resources if needed (edit deployment.yaml).

## Upgrading

### Rolling update

```bash
# Update image
kubectl set image deployment/est-service \
  est-service=est-service:v2.0.0 \
  -n est-service

# Monitor rollout
kubectl rollout status deployment/est-service -n est-service

# Rollback if needed
kubectl rollout undo deployment/est-service -n est-service
```

### Blue-Green deployment

1. Deploy new version with different label
2. Test new version
3. Switch service selector
4. Remove old deployment

## Backup and Recovery

### Backup configuration

```bash
kubectl get configmap est-service-config -n est-service -o yaml > backup-config.yaml
kubectl get secret est-service-tls -n est-service -o yaml > backup-tls.yaml
```

### Restore from backup

```bash
kubectl apply -f backup-config.yaml
kubectl apply -f backup-tls.yaml
kubectl rollout restart deployment/est-service -n est-service
```

## Production Checklist

- [ ] Valid TLS certificates (not self-signed)
- [ ] Secrets properly secured
- [ ] Resource limits configured
- [ ] HPA enabled
- [ ] PDB configured
- [ ] Monitoring enabled (Prometheus)
- [ ] Logging configured (ELK/Loki)
- [ ] Network policies applied
- [ ] Backup strategy in place
- [ ] Disaster recovery plan
- [ ] Security scanning enabled
- [ ] Rate limiting configured
- [ ] Backend high availability

## Next Steps

- Configure cert-manager for automated certificate rotation
- Set up Istio/service mesh for mTLS
- Implement GitOps with ArgoCD/Flux
- Configure alerts in Alertmanager
- Set up centralized logging
