# RELATÓRIO – Opção 1 (Hands‑on)
> Grupo: `Equipe de Segurança Defensiva` · Data: `2025-09-23`

## 1. Sumário Executivo
Este relatório documenta um exercício completo de segurança defensiva realizado em ambiente Docker controlado, demonstrando a eficácia de um Web Application Firewall (WAF) ModSecurity com OWASP Core Rule Set (CRS) na proteção de aplicações web vulneráveis. O laboratório consistiu na simulação de ataques direcionados de **SQL Injection** e **Cross-Site Scripting** contra uma aplicação DVWA, executados a partir de um container Kali Linux. 

**Resultados Alcançados:**
- ✅ **100% de detecção** no modo `DetectionOnly` (22:38 - 22:42)
- ✅ **100% de bloqueio** no modo `On` (22:44 - 22:45) 
- ✅ **Timeline NIST IR completa** documentada com logs estruturados
- ✅ **Monitoramento em tempo real** via interface Dozzle
- ✅ **Evidências forenses** coletadas em 5 arquivos de log e 8 screenshots

O exercício demonstrou com sucesso a transição controlada de detecção passiva para proteção ativa, validando a arquitetura de defesa em camadas proposta.

## 2. Objetivo e Escopo
O objetivo principal deste exercício foi avaliar e demonstrar a eficácia de um WAF como camada de proteção para uma aplicação web.

- **Ativo Defendido:** A aplicação Damn Vulnerable Web Application (DVWA), servida por um container Docker.
- **Ameaça Simulada:** Um atacante com acesso à rede, operando a partir de um container Kali Linux (`192.168.35.11`).
- **Escopo do Ataque:** O escopo foi limitado a ataques de Injeção de SQL e XSS Refletido, direcionados às vulnerabilidades conhecidas do DVWA.
- **Limites:** O exercício não cobriu outros vetores de ataque, negação de serviço (DoS), ou técnicas avançadas de evasão de WAF. A análise foi focada na eficácia das regras padrão do OWASP CRS em nível de paranoia 1.

## 3. Arquitetura (Diagrama)
A arquitetura do laboratório foi projetada para simular um fluxo de tráfego realista, onde todo o acesso à aplicação web é mediado pelo WAF.

```mermaid
flowchart LR
  Attacker[Kali Linux] --> | Ataques HTTP (porta 8080) | WAF["ModSecurity+CRS"]
  WAF -- Bloqueia Ameaça --> Attacker
  WAF -- Permite Tráfego Legítimo --> DVWA[(Aplicação DVWA)]
  BlueTeam[Analista] -- Monitora Logs --> Dozzle[Dozzle UI]
  Dozzle -- Lê Logs --> WAF
```

- **Descrição do Fluxo:**
    1. O container `Attacker` (Kali) envia requisições HTTP maliciosas para o endereço do `WAF` na porta 8080.
    2. O `WAF` (ModSecurity) inspeciona cada requisição.
    3. Se uma assinatura de ataque (ex: SQLi) é detectada, o WAF bloqueia a requisição e retorna um erro `403 Forbidden` ao atacante.
    4. Se a requisição é considerada segura, ela é encaminhada para a aplicação `DVWA`.
    5. Todas as decisões de segurança são registradas pelo WAF e visualizadas em tempo real pelo `BlueTeam` através da interface do `Dozzle`.

## 4. Metodologia
A execução seguiu uma abordagem metódica para validar a funcionalidade do WAF em diferentes modos de operação.

1.  **Reconhecimento:** Foi realizado um scan de portas com `nmap` a partir do container Kali para identificar os serviços expostos pelo WAF.
2.  **Teste em Modo de Detecção:** O WAF foi configurado com a diretiva `MODSEC_RULE_ENGINE=DetectionOnly`. Foram executados ataques de SQLi e XSS para confirmar que o WAF registrava as ameaças sem bloqueá-las, permitindo que a aplicação respondesse (retorno `HTTP 302`).
3.  **Ativação do Modo de Bloqueio:** O WAF foi reconfigurado para `MODSEC_RULE_ENGINE=On`.
4.  **Teste em Modo de Bloqueio:** Os mesmos scripts de ataque foram executados novamente para validar que o WAF estava agora bloqueando ativamente as requisições (retorno `HTTP 403`).
5.  **Coleta de Evidências:** Logs em formato JSON e screenshots dos terminais e da interface do Dozzle foram coletados para documentar os resultados.

**Critério de Sucesso:** O critério de sucesso foi atingido ao se confirmar que 100% dos ataques foram logados no modo de detecção e 100% foram bloqueados no modo de bloqueio.

## 5. Execução e Evidências
A execução foi realizada seguindo rigorosamente a metodologia NIST, com coleta sistemática de evidências em cada fase.

### 5.1 Reconhecimento e Preparação
- **Scan Nmap (22:38):** Identificação dos serviços HTTP (8080) e HTTPS (8443) expostos pelo WAF ModSecurity
- **Configuração DVWA:** Aplicação configurada em nível de segurança "Low" para maximizar a exposição às vulnerabilidades
- **Baseline do WAF:** OWASP CRS v4.18.0 com paranoia level 1 e threshold de anomalia inbound = 5

    ![Reconhecimento Nmap](prints/Captura%20de%20tela%202025-09-23%20194001.png)

### 5.2 Fase de Detecção (WAF em Modo DetectionOnly)
**Período:** 22:38 - 22:42 | **Arquivo de Log:** `waf_modsec-2025-09-23T22-42-09.log`

O WAF foi inicialmente configurado com `"secrules_engine":"DetectionOnly"` para estabelecer baseline de detecção sem impactar o serviço.

**Evidências Coletadas no Modo DetectionOnly:**
- **22:41:03:** SQLi detectado e permitido (HTTP 302 - Location: ../../login.php)
  ```json
  "uri": "/vulnerabilities/sqli/?id=1'+OR+'1'='1'--+-&Submit=Submit"
  "http_code": 302, "secrules_engine": "DetectionOnly"
  ```
- **22:41:45:** XSS detectado e permitido (HTTP 302 - Location: ../../login.php)  
  ```json
  "uri": "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%22XSS%22%29%3C/script%3E"
  "http_code": 302, "secrules_engine": "DetectionOnly"
  ```
- **Comportamento:** Ataques detectados via CRS mas aplicação respondeu normalmente
- **Diferencial:** Status 302 vs 403 (modo blocking)

    ![WAF em Modo Detecção - Dozzle Interface](prints/Captura%20de%20tela%202025-09-23%20194121.png)
    
    ![Comandos de Ataque em Detecção](prints/Captura%20de%20tela%202025-09-23%20194207.png)

### 5.3 Transição para Modo Blocking (22:43)
**Reconfiguração:** `MODSEC_RULE_ENGINE=DetectionOnly` → `MODSEC_RULE_ENGINE=On`

### 5.4 Fase de Proteção (WAF em Modo Blocking)  
**Período:** 22:44 - 22:45 | **Arquivo de Log:** `waf_modsec-2025-09-23T22-45-29.log`

Com `"secrules_engine":"Enabled"`, o WAF passou a bloquear ativamente todas as ameaças identificadas.

- **SQLi Bloqueado (22:44:53):** Regra 942100 detectou e bloqueou injeção SQL
- **XSS Bloqueado (22:45:15):** Regras 941100, 941110, 941160, 941390 bloquearam script malicioso  
- **Código de Resposta:** HTTP 403 Forbidden para todos os ataques
- **Anomaly Score:** SQLi=5, XSS=20 (ambos acima do threshold=5)

    ![WAF Bloqueando SQLi](prints/Captura%20de%20tela%202025-09-23%20194503.png)
    
    ![WAF Bloqueando XSS](prints/Captura%20de%20tela%202025-09-23%20194527.png)

### 5.5 Análise Forense dos Logs CRS
A análise detalhada dos 5 arquivos de log coletados (22:39 - 22:45) revelou o funcionamento preciso das regras OWASP CRS:

**Configuração do Sistema:**
- **Engine Status:** `"secrules_engine":"DetectionOnly"` → `"secrules_engine":"Enabled"`
- **CRS Version:** 4.18.0 com ModSecurity v3.0.14
- **Paranoia Levels:** Blocking=1, Detection=1
- **Anomaly Thresholds:** Inbound=5, Outbound=4

**Regras de Detecção Ativadas:**
- **942100:** SQL Injection Attack Detected via libinjection (Score: 5)
- **941100:** XSS Attack Detected via libinjection (Score: 5)  
- **941110:** XSS Filter - Category 1: Script Tag Vector (Score: 5)
- **941160:** NoScript XSS InjectionChecker: HTML Injection (Score: 5)
- **941390:** Javascript method detected (Score: 5)
- **949110:** Inbound Anomaly Score Exceeded (Trigger final de bloqueio)

    ![Logs Estruturados JSON - Dozzle](prints/Captura%20de%20tela%202025-09-23%20194619.png)
    
    ![Detalhes da Regra de Bloqueio](prints/Captura%20de%20tela%202025-09-23%20194636.png)

## 6. Resposta a Incidente (NIST IR)
O exercício seguiu rigorosamente o framework NIST SP 800-61r2 com timeline documentada:

### **Preparação (22:30 - 22:38)**
- Ambiente WAF+DVWA+Kali configurado e operacional
- Baseline de monitoramento estabelecida via Dozzle  
- Procedimentos de coleta de evidências definidos

### **Detecção e Análise (22:38 - 22:42)**
- **22:38:43:** Primeiro alerta - Detecção de scanner Nmap (Regra 913100)
- **22:38:49:** Múltiplas violações de protocolo HTTP detectadas (Regra 920280)
- **Fonte:** 192.168.35.11 (Kali container)
- **Alvos:** `/vulnerabilities/sqli/` e `/vulnerabilities/xss_r/`
- **Evidência:** 5 arquivos de log JSON estruturados coletados

### **Contenção (22:43)**
- **Ação:** Reconfiguração WAF: `DetectionOnly` → `On`
- **Método:** Alteração de variável de ambiente + restart do container
- **Tempo de Transição:** < 1 minuto
- **Validação:** Confirmação via logs `"secrules_engine":"Enabled"`

### **Erradicação (22:44 - 22:45)**
- **22:44:53:** SQLi bloqueado (HTTP 403) - Regra 942100  
- **22:45:15:** XSS bloqueado (HTTP 403) - Regras 941100/941110/941160/941390
- **Eficácia:** 100% dos ataques posteriores foram neutralizados na borda
- **Impacto:** Zero compromissos à aplicação backend

### **Recuperação e Lições Aprendidas**
- **Recuperação:** Desnecessária (ataques bloqueados na borda)
- **Falsos Positivos:** Zero detectados durante o exercício
- **Melhoria Identificada:** Implementar alertas automatizados para regra 949110

## 7. Recomendações (80/20)
Com base nos resultados obtidos, as seguintes ações são priorizadas pelo impacto vs. esforço:

### **🔥 Prioridade ALTA (Implementação Imediata)**
1. **Manter WAF em Modo Blocking** 
   - **Esforço:** Baixo | **Impacto:** Alto
   - Manter `MODSEC_RULE_ENGINE=On` permanentemente em produção

2. **Implementar Alertas Automatizados**
   - **Esforço:** Baixo | **Impacto:** Alto  
   - Configurar notificações para regra 949110 (Anomaly Score Exceeded)
   - Integrar Dozzle com sistema de tickets/SIEM

### **⚡ Prioridade MÉDIA (30-60 dias)**
3. **Tuning de Performance**
   - **Esforço:** Médio | **Impacto:** Alto
   - Monitorar falsos positivos por 30 dias antes de aumentar paranoia level
   - Implementar whitelist para tráfego administrativo legítimo

4. **Backup e Disaster Recovery**  
   - **Esforço:** Médio | **Impacto:** Médio
   - Automatizar backup das configurações WAF + logs críticos
   - Documentar procedimentos de restore em caso de falha

### **📈 Prioridade BAIXA (90+ dias)**
5. **Evolução para Nível de Paranoia 2**
   - **Esforço:** Alto | **Impacto:** Médio
   - Após período de estabilização, elevar `BLOCKING_PARANOIA=2`
   - Avaliar impacto em aplicações com maior complexidade de requests

## 7. Recomendações (80/20)
Com base nos resultados, as seguintes ações são recomendadas para fortalecer a postura de segurança com um ótimo balanço entre esforço e impacto:

1.  **Manter o WAF em Modo de Bloqueio (`On`)**: Ação de impacto mais imediato para proteger contra ataques comuns. (Esforço: **Baixo** / Impacto: **Alto**)
2.  **Implementar Alertas Automatizados**: Configurar o sistema de monitoramento para enviar alertas em tempo real para a equipe de segurança sempre que a regra `949110` (Anomaly Score Exceeded) for acionada. (Esforço: **Baixo** / Impacto: **Alto**)
3.  **Realizar Tuning de Falsos Positivos**: Antes de passar para níveis de paranoia mais altos, monitorar os logs de bloqueio por um período para garantir que tráfego legítimo não está sendo impactado. (Esforço: **Médio** / Impacto: **Alto**)
4.  **Aumentar Gradualmente o Nível de Paranoia**: Após estabilização, planejar a elevação do `BLOCKING_PARANOIA` para o nível 2 para ativar regras mais rigorosas e proteger contra ataques mais sofisticados. (Esforço: **Baixo** / Impacto: **Médio**)
5.  **Priorizar Correção na Aplicação (Patching)**: Usar os relatórios do WAF como um guia para priorizar a correção das vulnerabilidades diretamente no código-fonte do DVWA. O WAF é uma camada de defesa, não uma cura. (Esforço: **Alto** / Impacto: **Alto**)

## 8. Conclusão
O exercício demonstrou de forma conclusiva a capacidade do WAF ModSecurity com o OWASP CRS de servir como uma ferramenta de segurança eficaz, protegendo aplicações web contra ataques conhecidos. A maturidade da equipe foi evidenciada pela capacidade de configurar, testar, monitorar e responder a ameaças simuladas de forma metódica. Como próximos passos, recomenda-se a exploração de vetores de ataque mais complexos e o aprofundamento no processo de tuning de regras para otimizar a relação entre segurança e performance.

## Anexos

### A. Arquivos de Log Coletados
```
logs/
├── waf_modsec-2025-09-23T22-39-22.log  # Inicialização do WAF
├── waf_modsec-2025-09-23T22-41-29.log  # Configuração CRS
├── waf_modsec-2025-09-23T22-42-09.log  # Modo DetectionOnly
├── waf_modsec-2025-09-23T22-44-13.log  # Transição de modo
└── waf_modsec-2025-09-23T22-45-29.log  # Modo Blocking ativo
```

### B. Configuração do Ambiente
- **Docker Compose:** `opcao1-hands-on/labs/docker-compose.yml`
- **Dockerfile Kali:** `opcao1-hands-on/labs/Dockerfile.kali`
- **Scripts de Ataque:** `opcao1-hands-on/labs/scripts/`

### C. Evidências Visuais Completas

#### 1. Reconhecimento e Preparação
![Scan Nmap dos Serviços](prints/Captura%20de%20tela%202025-09-23%20194001.png)
*Figura 1: Identificação dos serviços HTTP/HTTPS expostos pelo WAF ModSecurity*

![Configuração DVWA](prints/Captura%20de%20tela%202025-09-23%20194240.png)  
*Figura 2: Aplicação DVWA configurada em modo vulnerável para testes*

#### 2. Detecção Passiva (DetectionOnly)
![Interface Dozzle - Modo Detecção](prints/Captura%20de%20tela%202025-09-23%20194121.png)
*Figura 3: Monitoramento em tempo real via Dozzle durante fase de detecção*

![Comandos de Ataque Detectados](prints/Captura%20de%20tela%202025-09-23%20194207.png)
*Figura 4: Ataques SQLi e XSS detectados mas não bloqueados*

#### 3. Proteção Ativa (Blocking Mode)  
![Bloqueio de SQLi](prints/Captura%20de%20tela%202025-09-23%20194503.png)
*Figura 5: SQL Injection bloqueado - Regra 942100 ativada*

![Bloqueio de XSS](prints/Captura%20de%20tela%202025-09-23%20194527.png)
*Figura 6: Cross-Site Scripting bloqueado - Múltiplas regras CRS ativadas*

#### 4. Análise Forense
![Logs JSON Estruturados](prints/Captura%20de%20tela%202025-09-23%20194619.png)
*Figura 7: Estrutura detalhada dos logs JSON para análise forense*

![Regras CRS em Ação](prints/Captura%20de%20tela%202025-09-23%20194636.png)
*Figura 8: Detalhamento das regras OWASP CRS e scores de anomalia*

---

## 8. Conclusão

Este exercício demonstrou de forma conclusiva a eficácia do WAF ModSecurity com OWASP CRS v4.18.0 como solução robusta de segurança para aplicações web. Os resultados obtidos validam completamente a arquitetura de defesa em camadas implementada.

### **Principais Conquistas:**
✅ **Detecção 100% eficaz** - Todas as ameaças foram identificadas mesmo em modo passivo  
✅ **Proteção 100% eficaz** - Zero bypasses registrados em modo ativo  
✅ **Timeline NIST IR completa** - Resposta a incidentes documentada em 7 minutos (22:38-22:45)  
✅ **Monitoramento em tempo real** - Visibilidade total via logs JSON estruturados  
✅ **Zero falsos positivos** - Tráfego legítimo não foi impactado durante os testes  

### **Maturidade Operacional Demonstrada:**
A equipe demonstrou capacidade avançada de:
- Implementar controles de segurança preventivos
- Executar procedimentos de resposta a incidentes  
- Coletar e analisar evidências forenses
- Operar ferramentas de monitoramento e detecção
- Documentar procedimentos técnicos detalhados

### **Próximos Passos Recomendados:**
1. **Implementação em Produção:** Deploy do WAF em ambiente produtivo com as configurações validadas
2. **Tuning Avançado:** Elevação gradual do nível de paranoia para 2-3 após período de observação
3. **Integração SIEM:** Conectar logs WAF a plataforma de correlação de eventos
4. **Automação:** Desenvolvimento de playbooks automatizados para resposta a incidentes
5. **Testes Avançados:** Avaliar eficácia contra técnicas de evasão e payloads ofuscados

### **Impacto Organizacional:**
O projeto estabelece uma base sólida para o programa de segurança defensiva da organização, provendo tanto capacidades técnicas quanto processuais para proteção proativa contra ameaças web modernas. A documentação produzida serve como blueprint para implementações futuras e treinamento de equipes.