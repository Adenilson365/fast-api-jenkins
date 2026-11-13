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
        
        stage('Docker Build') {
            agent {
                label 'buildkit'
            }

            environment {
                IMAGE_REPO = 'adenilsonkon/jenkins-fastapi'
            }

            steps {
                checkout scm

                script {
                    def safeBranch = env.BRANCH_NAME
                        .replaceAll(/[^a-zA-Z0-9_.-]/, '-')
                        .toLowerCase()

                    env.IMAGE_TAG = "${safeBranch}-${env.BUILD_NUMBER}"
                    env.IMAGE_REF = "${env.IMAGE_REPO}:${env.IMAGE_TAG}"

                    echo "Imagem: ${env.IMAGE_REF}"
                }

                // BuildKit
                sh '''
                    set -eu

                    docker buildx build \
                        --platform linux/amd64 \
                        --progress=plain \
                        --load \
                        -t "$IMAGE_REF" \
                        .

                    docker image inspect "$IMAGE_REF"
                '''
            }

            post {
                always {
                    echo "Build finalizado."
                }
            }
        }

        stage('Trivy Image'){
            sh '''
                    set -eu
                    HTML_TEMPLATE="/opt/trivy/templates/html.tpl"
                    if [ -n "${IMAGE_REF:-}" ]; then

                            echo "=== SCAN DA IMAGEM ==="

                            trivy image \
                            --scanners vuln \
                            --format json \
                            --exit-code 0 \
                            --output reports/trivy-image.json \
                            "$IMAGE_REF"

                            echo "=== GERANDO HTML DA IMAGEM ==="

                            trivy convert \
                            --format template \
                            --template "@${HTML_TEMPLATE}" \
                            --output reports/trivy-image.html \
                            reports/trivy-image.json

                            set -- "$@" reports/trivy-image.json

                        else
                            echo "IMAGE_REF vazio."
                            echo "Scan de imagem ignorado."
                        fi
                        '''
        }

        stage('Docker Push'){

                // Autenticação e push
                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub-credentials',
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_TOKEN'
                    )
                ]) {
                    sh '''
                        set +x
                        set -eu

                        export DOCKER_CONFIG="$(mktemp -d)"
                        trap 'rm -rf "$DOCKER_CONFIG"' EXIT

                        printf '%s' "$DOCKER_TOKEN" |
                            docker login \
                                --username "$DOCKER_USER" \
                                --password-stdin

                        docker push "$IMAGE_REF"
                    '''
                }
        }

    }

}