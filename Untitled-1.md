helm install mw-agent middleware-labs/mw-kube-agent-v3 \
--set global.mw.apiKey=ytwcxcdbffhpjfmfzyrozxaealrvtnqahitp \
--set global.mw.target=https://kbuin.beta.env.middleware.io:443 \
--set mw.apiUrlForConfigCheck=https://kbuin.beta.env.middleware.io \
--set global.clusterMetadata.name=npm-cluster \
-n mw-agent-ns --create-namespace