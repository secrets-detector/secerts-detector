{{/*
Expand the name of the chart.
*/}}
{{- define "secrets-detector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "secrets-detector.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "secrets-detector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "secrets-detector.labels" -}}
helm.sh/chart: {{ include "secrets-detector.chart" . }}
{{ include "secrets-detector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "secrets-detector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secrets-detector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "secrets-detector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "secrets-detector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
GitHub App labels
*/}}
{{- define "secrets-detector.githubAppLabels" -}}
{{ include "secrets-detector.labels" . }}
app.kubernetes.io/component: github-app
{{- end }}

{{/*
GitHub App selector labels
*/}}
{{- define "secrets-detector.githubAppSelectorLabels" -}}
{{ include "secrets-detector.selectorLabels" . }}
app.kubernetes.io/component: github-app
{{- end }}

{{/*
Validation Service labels
*/}}
{{- define "secrets-detector.validationServiceLabels" -}}
{{ include "secrets-detector.labels" . }}
app.kubernetes.io/component: validation-service
{{- end }}

{{/*
Validation Service selector labels
*/}}
{{- define "secrets-detector.validationServiceSelectorLabels" -}}
{{ include "secrets-detector.selectorLabels" . }}
app.kubernetes.io/component: validation-service
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "secrets-detector.postgresLabels" -}}
{{ include "secrets-detector.labels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "secrets-detector.postgresSelectorLabels" -}}
{{ include "secrets-detector.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
Grafana labels
*/}}
{{- define "secrets-detector.grafanaLabels" -}}
{{ include "secrets-detector.labels" . }}
app.kubernetes.io/component: grafana
{{- end }}

{{/*
Grafana selector labels
*/}}
{{- define "secrets-detector.grafanaSelectorLabels" -}}
{{ include "secrets-detector.selectorLabels" . }}
app.kubernetes.io/component: grafana
{{- end }}

{{/*
Return the PostgreSQL hostname
*/}}
{{- define "secrets-detector.postgresHost" -}}
{{- if .Values.postgres.enabled }}
{{- printf "%s-postgres" (include "secrets-detector.fullname" .) }}
{{- else }}
{{- .Values.postgres.externalPostgres.host }}
{{- end }}
{{- end }}

{{/*
Return the PostgreSQL port
*/}}
{{- define "secrets-detector.postgresPort" -}}
{{- if .Values.postgres.enabled }}
{{- .Values.postgres.service.port | toString }}
{{- else }}
{{- .Values.postgres.externalPostgres.port | toString }}
{{- end }}
{{- end }}

{{/*
Return the PostgreSQL secret name
*/}}
{{- define "secrets-detector.postgresSecretName" -}}
{{- if .Values.postgres.credentials.existingSecret }}
{{- .Values.postgres.credentials.existingSecret }}
{{- else }}
{{- printf "%s-postgres" (include "secrets-detector.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the GitHub App secret name
*/}}
{{- define "secrets-detector.githubSecretName" -}}
{{- if .Values.githubApp.githubSecret.existingSecret }}
{{- .Values.githubApp.githubSecret.existingSecret }}
{{- else }}
{{- printf "%s-github" (include "secrets-detector.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the Grafana secret name
*/}}
{{- define "secrets-detector.grafanaSecretName" -}}
{{- if .Values.grafana.credentials.existingSecret }}
{{- .Values.grafana.credentials.existingSecret }}
{{- else }}
{{- printf "%s-grafana" (include "secrets-detector.fullname" .) }}
{{- end }}
{{- end }}