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
    }

}