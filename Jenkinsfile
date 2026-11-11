pipeline{
    agent none
    options{
        timeout(time:30, unit: 'MINUTES')
        timestamps()
        disableConcurrentBuilds()
    }
    stages{
        stage('Trivy Source'){
            agent {label 'trivy'}
            steps{
                sh '''
                     set -eu

                    mkdir -p reports

                    HTML_TEMPLATE="/opt/trivy/templates/html.tpl"

                    echo "=== VERSOES ==="
                    trivy --version
                    jq --version

                    if [ ! -s "$HTML_TEMPLATE" ]; then
                        echo "ERRO: Template HTML nao encontrado:"
                        echo "$HTML_TEMPLATE"
                        exit 1
                    fi

                    # ====================================
                    # SCAN DO REPOSITORIO
                    # ====================================

                    echo "=== SCAN DO REPOSITORIO ==="

                    trivy fs \
                      --scanners vuln,misconfig \
                      --format json \
                      --exit-code 0 \
                      --output reports/trivy-source.json \
                      .

                    echo "=== GERANDO HTML DO REPOSITORIO ==="

                    trivy convert \
                      --format template \
                      --template "@${HTML_TEMPLATE}" \
                      --output reports/trivy-source.html \
                      reports/trivy-source.json

                    set -- reports/trivy-source.json

                                        # ====================================
                    # RESUMO COM JQ
                    # ====================================

                    echo "=== RESUMO DE SEGURANCA ==="

                    jq -s -r '
                      . as $reports |
                      (["Tipo","Severidade","Qtd"] | @tsv),
                      (
                        ["Vulnerabilities","Misconfigurations"][]
                        as $type |
                        ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"][]
                        as $severity |
                        [
                          $type,
                          $severity,
                          ([
                            $reports[]
                            | .Results[]?
                            | .[$type][]?
                            | select(.Severity == $severity)
                          ] | length | tostring)
                        ] | @tsv
                      )
                    ' "$@" | tee reports/resumo.tsv

                    # ====================================
                    # CVES HIGH E CRITICAL
                    # ====================================

                    echo "=== CVES HIGH E CRITICAL ==="

                    jq -s -r '
                      ([
                        "Severidade", "CVE", "Pacote",
                        "Instalada", "Corrigida", "Alvo"
                      ] | @tsv),
                      (
                        .[] | .Results[]? as $r |
                        $r.Vulnerabilities[]? |
                        select(
                          .Severity == "HIGH" or
                          .Severity == "CRITICAL"
                        ) |
                        [
                          .Severity,
                          .VulnerabilityID,
                          .PkgName,
                          .InstalledVersion,
                          (.FixedVersion // "N/A"),
                          $r.Target
                        ] | @tsv
                      )
                    ' "$@" | tee reports/cves.tsv

                    # ====================================
                    # MISCONFIGURATIONS
                    # ====================================

                    echo "=== CONFIGURACOES INSEGURAS ==="

                    jq -r '
                      ([
                        "Severidade", "ID", "Regra", "Alvo"
                      ] | @tsv),
                      (
                        .Results[]? as $r |
                        $r.Misconfigurations[]? |
                        select(
                          .Severity == "HIGH" or
                          .Severity == "CRITICAL"
                        ) |
                        [
                          .Severity,
                          .ID,
                          (.Title // "N/A"),
                          $r.Target
                        ] | @tsv
                      )
                    ' reports/trivy-source.json |
                      tee reports/misconfig.tsv
                '''
            }
            post {
                always {
                    archiveArtifacts(
                        artifacts: 'reports/**/*',
                        allowEmptyArchive: true
                    )

                    script {
                        if (fileExists('reports/trivy-source.html')) {
                            publishHTML(target: [
                                reportDir: 'reports',
                                reportFiles: 'trivy-source.html',
                                reportName: 'Trivy - Source Scan',
                                keepAll: true,
                                alwaysLinkToLastBuild: true,
                                allowMissing: false
                            ])
                        }
                    }
                }
            }
        }
        stage('Build'){
            agent{label 'buildkit'}
            environment{
                DOCKER_HUB_USER = credentials('DOCKER_HUB_USER')
                DOCKER_HUB_PASS = credentials('DOCKER_HUB_PASS')
            }
            steps{
                sh '''
                docker buildx build \
                --platform linux/amd64 \
                --progress=plain \
                -t adenilsonkon/jenkins-fastapi-${BRANCH_NAME}:${BUILD_NUMBER} \
                --load \
                .
                '''
                sh '''
                    docker login -u $DOCKER_HUB_USER -p $DOCKER_HUB_PASS
                '''
                sh '''
                    docker buildx build \
                    --platform linux/amd64 \
                    --progress=plain \
                    -t adenilsonkon/jenkins-fastapi-${BRANCH_NAME}:${BUILD_NUMBER} \
                    --push \
                    .
            
                '''
            }
            post {
                always{
                    echo "Image: adenilsonkon/jenkins-fastapi-${BRANCH_NAME}:${BUILD_NUMBER}"
                }
            }
        }
    }

}