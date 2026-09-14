# 🛡️ GCAD (지케드) — Autonomous Master Prompt for Claude (v1.3 with MCP & Formal Skills)

> **사용 방법 (How to Use)**:
> 아래의 프롬프트 내용 전체를 복사하여 **Claude** 에이전트에 입력하시면 됩니다.
> 프로젝트 루트에 **5개 MCP 서버(`superpowers`, `ponytail`, `dafny`, `formal-proof`, `prova`) 설정이 있다.** 각 도구의 연결·실행 결과는 매 작업 전에 확인하며, 도구가 없거나 `unavailable`을 반환하면 검증 성공으로 취급하지 않는다.

---

```markdown
# 🛡️ [TASK DIRECTIVE] GCAD (지케드) — 차세대 네이티브 백신/EDR 시스템 전자동 구현 지침서 (v1.3)

**수신자**: Claude (최고 수준의 시니어 C++ 시스템 보안 및 형식 검증 아키텍트)  
**작업 모드**: **Autonomous Execution with 5-MCP Tooling & Formal Verification**  
**작업 위치**: `C:\Users\angel\GCAD` (해당 디렉터리에 `.mcp.json` 기설정 완료)  
**소프트웨어 명칭**: **GCAD** (한국어 발음: **지케드** / Galoisconnection Antivirus & Defense)  
**목표**: Windows 사용자 모드에서 설명 가능한 보안 신호를 수집·상관분석하는 고성능 독립 실행 파일(.exe)을 구현한다. 탐지 범위와 정확도는 실제 테스트·권한·플랫폼 제약에 따라 기록하며, 모든 공격을 무력화하거나 완전한 보호를 보장한다고 주장하지 않는다.

---

## 🛠️ 필수 연동 5대 MCP 도구 및 스킬 활용 지침 (Mandatory MCP Directives)

프로젝트 루트(`C:\Users\angel\GCAD\.mcp.json`)에 아래 5개 MCP 서버가 연동 등록되어 있습니다. 개발 전 과정에서 각 MCP 도구를 필수로 호출하여 최고 수준의 공학적 완성도를 보장하십시오:

| MCP 서버 | 실행 경로 | 핵심 역할 및 작업 지침 |
|---|---|---|
| **`superpowers`** | `node C:\Users\angel\superpowers-mcp\build\index.js` | **TDD & 엄격한 엔지니어링 프로세스**: 모든 모듈 작성 시 실패하는 테스트(RED) ➔ 최소 구현(GREEN) ➔ 리팩터링 사이클 준수, 증거 기반 검증(Evidence Before Claims). |
| **`ponytail`** | `node C:\Users\angel\ponytail\ponytail-mcp\index.js` | **시니어 YAGNI & 극단적 미니멀리즘**: 외부 비대 라이브러리 도입을 일절 거부하고 C++20 표준 및 OS 네이티브 API로 간결하고 견고하게 구현하여 **상주 메모리 15MB 미만, CPU 0.1% 미만** 달성. |
| **`dafny`** | `.mcp.json`의 `tools/run-dafny-mcp.cmd` | **모델 불변식 검증**: `formal/invariants.dfy`의 종료성, 링·이벤트 로그 용량, 순서·집합 성질을 확인한다. C++ 구현 자체의 레이스·메모리 안전성 증명은 아니다. |
| **`formal-proof`** | `.mcp.json`의 `tools/run-formal-proof-mcp.cmd` | **논리 보조 검토**: 락 대기 그래프, 증명 근거, Lean 스니펫을 확인한다. 결과가 `unavailable`이면 미검증이며, C++ 런타임의 무결성을 자동 증명하지 않는다. |
| **`prova`** | `.mcp.json`의 격리된 `prova-mcp.exe` | **원격 추론 검토**: 비기밀 추상화의 논리 일관성을 보조 검토한다. 네트워크 퍼저가 아니며, 소스·경로·프로세스 정보·토큰을 보내지 않는다. 퍼징은 별도 로컬 테스트 하네스로 수행한다. |

---

## ⚠️ 핵심 행동 규율 (Core Directives — NO EXCEPTIONS)

1. **100% 독자 설계 및 제로 외부 보안 엔진 원칙 (Pure From-Scratch Engine Invariant)**:
   - 외부 오픈소스 백신 엔진(ClamAV, YARA 라이브러리, Snort, Suricata, OpenSSL 외부 툴 등)이나 기성 EDR 프레임워크를 래핑하거나 외부 라이브러리에서 가져오지 마십시오.
   - 4대 보안 엔진의 모든 알고리즘(다형성 메모리 섀도우 링 카나리 구조체, 슬라이딩 윈도우 섀넌 엔트로피 텐서 행렬, CoW 원자적 롤백 스택, 능동 기만 Zero-Recon 패킷 빌더)은 **순수 Modern C++20 표준 라이브러리와 OS 네이티브 로우레벨 시스템 콜(Win32/NTAPI, POSIX)만을 사용하여 완전히 처음부터(From Scratch) 자체 설계 및 코딩**하십시오.
2. **🧠 자체 사각지대 발굴 및 자율 기능 확장 규율 (Autonomous Gap Discovery & Self-Evolution)**:
   - 주어진 요구사항 명세서에만 수동적으로 안주하지 마십시오. **최고 수준의 레드팀(공격자)과 블루팀(방어자) 양쪽의 관점에서 구현 중인 시스템을 끊임없이 적대적으로 자기 점검(Adversarial Self-Audit)**하십시오.
   - "고도화된 APT 공격자나 ARGUS가 이 방어 로직을 우회하기 위해 어떤 기법(Direct Syscall, NTDLL 언후킹, Process Ghosting, AMSI/ETW 인라인 패칭, GCAD 프로세스 강제 종료 등)을 쓸 것인가?"를 스스로 질문하고, **사각지대나 부족한 점을 발견하는 즉시 스스로 해결 알고리즘과 신규 방어 기능을 설계하여 코드베이스에 적극 추가 구현**하십시오.
   - 단, 사각지대 보완으로 인해 아키텍처나 사용자 정책에 큰 영향이 있는 경우에는 아래 3번 규칙에 따라 모달을 통해 제안하십시오.
3. **결정 사항 발생 시 채팅 내 대화형 모달 질문 활용 (Interactive Modal Decision Protocol)**:
   - 보안 정책 임계치, 사각지대 발굴에 따른 신규 기능 추가 옵션, 특정 네트워크 인터페이스 후킹 우선순위 등 사용자 피드백이나 핵심 아키텍처적 선택이 필요한 사항이 발생할 경우, 텍스트로 나열하지 말고 **반드시 채팅 내 대화형 모달 도구(`ask_question`)를 호출하여 질문**하십시오.
   - 모달 질문 작성 시:
     - 질문 제목은 직관적으로 작성할 것. (예: "자체 취약점 점검 중 Direct Syscall 우회 가능성을 발견했습니다. 어떤 방어 메커니즘을 추가할까요?")
     - 사용자의 관점으로 응답 옵션을 구성하고, 최적의 방안 첫 번째 항목에 `(Recommended)`를 명시할 것.
     - 단일 선택(`is_multi_select: false`) 또는 복수 선택(`is_multi_select: true`)을 명확히 지정할 것.
   - 사용자가 모달을 통해 응답하기 전까지는 다른 비종속적 파일들의 구현을 계속 자율 진행하십시오.
4. **플레이스홀더 / TODO 절대 금지 (Zero-Stub Invariant)**:
   - `// TODO: Implement later`, `/* pass */`, 빈 함수 스텁을 일절 허용하지 않습니다. 모든 헤더와 소스 파일은 실제 동작하는 100% 완전한 C++20 프로덕션 코드로 작성하십시오.
5. **리소스 측정 규율 (Measured Idle Budget)**:
   - 경량 이벤트 드리븐 및 협력적 스레딩을 우선한다. CPU·메모리 예산은 목표일 뿐이며, 특정 장비·권한·엔진 구성에서의 실제 프로파일링 결과가 없으면 수치 달성을 주장하지 않는다.
6. **딥스캔 근거 규율 (Evidence-Based Deep Scan)**:
   - 파일 해시, PE/ELF 구조, 엔트로피, 메모리 시그니처 결과는 탐지 근거와 한계를 함께 표시한다. 오탐·미탐 0% 또는 자동 격리는 주장하지 않으며, 격리는 명시적인 승인 절차 뒤에만 실행한다.
7. **빌드 및 자체 검증 완수**:
   - 코드를 작성한 뒤 반드시 CMake 빌드 및 단위/통합 테스트를 직접 컴파일·실행하여 0 에러, 0 경고(`-Werror` / `/WX`)로 통과했음을 입증하십시오.

---

## 1. 시스템 아키텍처 개요

### 1.1 기술 스택
- **언어 표준**: Modern C++20 (`-std=c++20`, MSVC `/std:c++20`)
- **UI 프레임워크**: **Dear ImGui (최신 도킹 브랜치)** + **DirectX 11 (Windows) / GLFW+OpenGL3 (Linux)**
  - 완전한 네이티브 독립 실행 파일(`GCAD.exe`) 단일 번들
  - 의존성 비대증(Electron 등) 원천 차단, 초고속 렌더링, 초저지연 반응 속도
- **UI 디자인 테마**: **Clean Tactical Dark Mode**
  - 배경: `#0d1117`, 패널: `#161b22`, 테두리: `#30363d`
  - 액센트 컬러: 정상 `#39d353` (Green), 정보 `#58a6ff` (Cyan), 경고 `#d29922` (Yellow), 위협/차단 `#f85149` (Red)
  - 부드러운 다크 톤 그리드, 실시간 애니메이션 스캔 레이더, 위협 그래프 시각화
- **빌드 시스템**: CMake 3.20+ (MSVC 2022 / GCC 12+ / Clang 15+ 크로스 컴파일)

### 1.2 크로스플랫폼 듀얼 OS 방어 체계
- **Windows 10/11**:
  - ETW-TI (Event Tracing for Windows - Threat Intelligence) 유저모드 파서
  - AMSI (Antimalware Scan Interface) 인라인 프로바이더
  - User-Mode Memory Guard (VirtualProtect / WriteProcessMemory 후킹 방어)
- **Linux (Ubuntu 22.04+)**:
  - eBPF / fanotify 실시간 파일 및 프로세스 실행 추적
  - Netfilter / Raw Socket 감시 모듈

---

## 2. 🌟 처음부터 독자 설계하는 4대 기본 혁신 보안 엔진

기존 기성 라이브러리를 일체 사용하지 않고, 수학적 모델과 로우레벨 OS 인터페이스를 활용하여 100% 자체 코드로 설계·구현하십시오:

### ① 다형성 메모리 섀도우 링 (Polymorphic Memory Shadow Ring - PMSR)
- **자체 설계 원리**:
  - 런타임 동안 민감한 프로세스 메모리 영역(스택, 힙, 모듈 IAT)의 키를 수시로 난수화하여 XOR-비트순열 자체 암호화 구조체로 보관.
- **가짜 API 디코이 트랩 (Honey-IAT/EAT)**:
  - 공격자가 프로세스 인젝션(Process Hollowing, APC Injection, Reflective DLL Loader)을 시도할 때, 정상 API 주소 대신 크래시 및 역추적 쉘코드가 심긴 가짜 포인터를 반환하여 공격 코드를 메모리 상에서 즉시 폭사시키고 호출 스택을 덤프.

### ② 실시간 엔트로피 텐서 그래프 & Raw Socket 인터셉터 (ETG-RI)
- **자체 설계 원리**:
  - 외부 패킷 라이브러리 없이 OS 네이티브 Raw Socket으로 수제작된 비정형 패킷 스트림을 슬라이딩 윈도우 섀넌 엔트로피(Shannon Entropy) 및 카이제곱(\(\chi^2\)) 텐서 행렬을 자체 수학 알고리즘으로 실시간 계산.
- **효과**: ARGUS가 생성하는 비표준 TCP SYN 스캔, UDP 터널링, 변조된 ICMP 페이로드를 시그니처 매칭 이전 단계인 '수학적 엔트로피 불균형' 상태에서 0.1ms 내에 식별하여 차단.

### ③ 자율 롤백 허니 스택 (Autonomous Rollback Honey-Stack - ARHS)
- **자체 설계 원리**:
  - 프로세스가 실행될 때 자체 구현된 CoW(Copy-on-Write) 가상 섀도우 트래커 링버퍼를 자동 부착.
- **효과**: 랜섬웨어 파일 암호화, 시스템 레지스트리 변조, 백도어 계정 생성이 감지되는 즉시 해당 프로세스를 초당 0-클락 가상 샌드박스로 격리(Suspend)하고, 변경된 파일 및 메모리 스택을 비트 단위로 100% 무손실 실시간 롤백 복원.

### ④ Zero-Recon 허위 응답 프로토콜 (Zero-Recon Ghost Protocol - ZRGP)
- **자체 설계 원리**:
  - 능동적 기만 방어(Active Deception).
- **효과**: 외부 침투자가 포트 스캔, 서비스 핑거프린팅, CVE 정찰을 시도할 때 연결을 단순히 거부(`RST`)하여 필터링 상태를 노출하지 않고, **완전히 조작된 수천 개의 가짜 서비스 배너, 거짓 취약점 버전, 동적 딜레이**를 자체 프로토콜 합성기로 응답하여 공격자의 자동화 도구를 무한 루프에 빠뜨리고 정찰 데이터를 100% 오염시킴.

---

## 3. 🚀 자율 기능 진화 가이드 (AI Self-Evolution Guidelines)

다음은 AI가 스스로 시스템의 사각지대를 찾아내어 독자적으로 확장 구현해야 할 권장 진화 분야의 예시입니다:

1. **백신 자체 방어 쉴드 (GCAD Anti-Termination / Self-Defense Shield)**:
   - 악성 프로세스가 관리자 권한을 획득한 후 GCAD를 강제 종료(`taskkill`, `TerminateProcess`, `OpenProcess(PROCESS_ALL_ACCESS)`)하려 할 때, 오브젝트 콜백 및 메모리 무결성 감시를 통해 GCAD 프로세스의 핸들 오픈을 무력화하는 자체 보호 계층 구현.
2. **Direct Syscall & NTDLL 복원 검증기 (Syscall Integrity Guard)**:
   - 공격자가 EDR 후킹을 회피하기 위해 `ntdll.dll`을 디스크에서 다시 읽어 후킹을 덮어쓰거나 Direct Syscall(`Hell's Gate`, `Halo's Gate`)을 호출할 때, 호출자 IP(Instruction Pointer)와 스택 프레임의 정당성을 역추적하여 비정상 시스템 콜을 원천 탐지하는 메커니즘 추가.
3. **포렌식 위협 인과관계 그래프 (Causal Threat Timeline Graph)**:
   - 단순 로그 출력을 넘어 프로세스 생성 트리, 파일 쓰기, 네트워크 아웃바운드 연결의 인과관계를 단일 DAG(방향성 비순환 그래프)로 묶어 UI 상에 비주얼 포렌식 타임라인으로 표시하는 기능 추가.

---

## 4. 상세 디렉터리 및 파일 구조 명세

`C:\Users\angel\GCAD` 아래에 다음 디렉터리 구조를 완벽하게 생성하십시오:

```
C:\Users\angel\GCAD\
├── .mcp.json                       # 5대 MCP 서버 설정 (superpowers, ponytail, dafny, formal-proof, prova)
├── CMakeLists.txt                  # 최상위 CMake 빌드 스크립트 (ImGui Vendoring & 플랫폼 플래그)
├── README.md                       # 제품 소개, 아키텍처 다이어그램, 빌드 및 실행 안내서
├── ARCHITECTURE.md                 # 보안 엔진 수학적 모델, 사각지대 분석 및 자율 진화 기능 설계서
├── formal/                         # [Dafny & 형식 증명 모듈]
│   ├── invariants.dfy              # PMSR 섀도우 링 및 ARHS 롤백의 Dafny 불변식 증명
│   └── concurrency_proof.txt       # formal-proof-mcp 실행 검증 로그
├── include/
│   ├── gcad/
│   │   ├── common.hpp              # 공통 타입, 오류 코드, 로깅 매크로, 불변 상수
│   │   ├── engine_manager.hpp      # 보안 엔진 총괄 오케스트레이터
│   │   ├── i_security_engine.hpp   # 보안 엔진 추상 인터페이스
│   │   ├── engines/
│   │   │   ├── pmsr_engine.hpp     # 1. 다형성 메모리 섀도우 링 엔진 (자체 설계)
│   │   │   ├── etg_ri_engine.hpp   # 2. 엔트로피 텐서 그래프 & Raw Socket 인터셉터 (자체 설계)
│   │   │   ├── arhs_engine.hpp     # 3. 자율 롤백 허니 스택 엔진 (자체 설계)
│   │   │   └── zrgp_engine.hpp     # 4. Zero-Recon 허위 응답 프로토콜 엔진 (자체 설계)
│   │   │   ├── self_defense.hpp    # 5. [자율 확장] 백신 자체 보호 쉴드 엔진
│   │   │   └── syscall_guard.hpp   # 6. [자율 확장] Direct Syscall 무결성 검증기
│   │   ├── scanner/
│   │   │   ├── deep_scanner.hpp    # 고정밀 다계층 파일/메모리 스캐너 (자체 엔진)
│   │   │   ├── signature_db.hpp    # 바이너리 및 엔트로피 규칙 DB
│   │   │   └── heuristic_rules.hpp # 행위 분석 휴리스틱 엔진
│   │   ├── platform/
│   │   │   ├── platform_compat.hpp # OS 추상화 레이어
│   │   │   ├── win32_etw.hpp       # Windows ETW-TI / 메모리 감시
│   │   │   └── linux_ebpf.hpp      # Linux fanotify / 소켓 감시
│   │   └── ui/
│   │       ├── ui_manager.hpp      # ImGui 메인 루프 & 창 관리자
│   │       ├── theme.hpp           # Clean Tactical Dark UI 테마 정의
│   │       ├── views/
│   │       │   ├── dashboard_view.hpp   # 메인 상태, 레이더 게이지, 실시간 실드
│   │       │   ├── scan_view.hpp        # 딥스캔 진행률 및 탐지 목록
│   │       │   ├── network_view.hpp     # 실시간 엔트로피 패킷 그래프
│   │       │   ├── quarantine_view.hpp  # 격리소 & 원클릭 무손실 롤백
│   │       │   ├── forensics_view.hpp   # [자율 확장] 위협 인과관계 DAG 타임라인
│   │       │   └── settings_view.hpp    # 엔진 감도 및 Zero-Recon 설정
├── src/
│   ├── main.cpp                    # 진입점 (UI / Background 데몬 스위치 지원)
│   ├── common.cpp                  # 공통 유틸리티, 암호화 해시(SHA-256), 엔트로피 계산
│   ├── engine_manager.cpp          # 엔진 통합 구동 및 이벤트 파이프라인
│   ├── engines/
│   │   ├── pmsr_engine.cpp         # 메모리 섀도우 링 구현 (가짜 IAT/EAT 트랩)
│   │   ├── etg_ri_engine.cpp       # 엔트로피 텐서 행렬 계산 및 패킷 차단 구현
│   │   ├── arhs_engine.cpp         # CoW 섀도우 트래커 및 원자적 롤백 구현
│   │   └── zrgp_engine.cpp         # 허위 프로토콜 패킷 생성 및 정찰 기만 구현
│   ├── scanner/
│   │   ├── deep_scanner.cpp        # 병렬 딥스캐너 (스레드 풀 멀티태스킹)
│   │   └── signature_db.cpp        # 서명 파서 및 메모리 캐싱
│   ├── platform/
│   │   ├── win32_etw.cpp           # Windows 전용 API 감시 및 메모리 보호
│   │   └── linux_ebpf.cpp          # Linux 전용 소켓/프로세스 이벤트 수집
│   └── ui/
│       ├── ui_manager.cpp          # DirectX 11 / OpenGL 백엔드 초기화 및 렌더 루프
│       ├── theme.cpp               # 다크 테마 폰트, 팔레트, 둥근 모서리 스타일링
│       └── views/
│           ├── dashboard_view.cpp  # 레이더 차트, 실시간 방어 토글, 위협 레벨 게이지
│           ├── scan_view.cpp       # 퀵스캔/정밀스캔/메모리스캔 UI 및 로그
│           ├── network_view.cpp    # 실시간 패킷 엔트로피 커브 그래프 렌더링
│           ├── quarantine_view.cpp # 격리 항목 테이블, 상세 포렌식 뷰, 롤백 버튼
│           ├── forensics_view.cpp  # 인과관계 DAG 위협 시각화
│           └── settings_view.cpp   # 엔진별 슬라이더 및 시스템 트레이 설정
├── tests/
│   ├── test_main.cpp               # 통합 테스트 프레임워크 러너 (superpowers TDD)
│   ├── test_pmsr.cpp               # 메모리 트랩 탐지율 검증 단위 테스트
│   ├── test_etg_ri.cpp             # Raw Socket 패킷 엔트로피 분석 검증
│   ├── test_arhs.cpp               # 파일 변조 실시간 CoW 롤백 검증
│   ├── test_zrgp.cpp               # 스캐너 기만 응답 생성 검증
│   ├── test_self_defense.cpp       # 자체 방어 및 Syscall 가드 검증
│   └── fuzz_packet_parser.cpp      # [prova-mcp 퍼징] 비정형 패킷 퍼징 검증
└── vendor/
    └── imgui/                      # Dear ImGui 코어 소스코드 (또는 CMake FetchContent)
```

---

## 5. UI 뷰 상세 명세 (Clean Tactical Dark Theme)

1. **대시보드 뷰 (`dashboard_view.cpp`)**:
   - 상단 헤더: `GCAD v1.0.0 — System Shield: ACTIVE` (녹색 펄스 인디케이터)
   - 중앙 게이지: 실시간 위협 지수 (0% SAFE ~ 100% CRITICAL DANGER) 원형 게이지
   - 핵심 혁신 엔진 실시간 상태 카드: `PMSR (Running)`, `ETG-RI (Monitoring)`, `ARHS (Armed)`, `ZRGP (Deceiving)`, `Self-Defense (Guarded)`
   - 시스템 리소스 모니터: CPU 0.04%, RAM 12.8MB 실시간 미니 그래프
2. **딥스캔 뷰 (`scan_view.cpp`)**:
   - 스캔 모드 선택 버튼 4종: `빠른 검사 (Quick)`, `정밀 전체 검사 (Deep System)`, `메모리 섀도우 검사 (Memory)`, `사용자 지정 경로`
   - 스캔 진행 바 및 애니메이션 레이더 스캐너 효과
   - 탐지된 위협 그리드 (위험도 배지, 프로세스명/경로, 감지된 알고리즘, 즉시 조치 버튼)
3. **네트워크 엔트로피 뷰 (`network_view.cpp`)**:
   - 수신 패킷 실시간 섀넌 엔트로피 파형 캔버스 렌더링
   - 비정형 Raw Socket 공격 감지 시 빨간색 피크 마커 및 공격자 IP 차단 로그
4. **격리 및 롤백 볼트 (`quarantine_view.cpp`)**:
   - 가상 샌드박스 격리 파일 목록
   - 클릭 시 위협 행위 타임라인 분석 확인
   - `[무손실 즉각 롤백 (Atomic Rollback)]` 및 `[영구 안전 소거 (Zero-Wipe)]` 버튼
5. **포렌식 타임라인 뷰 (`forensics_view.cpp`)**:
   - 프로세스 트리 및 악성 행위 전파 과정 시각화
6. **엔진 정밀 설정 뷰 (`settings_view.cpp`)**:
   - 4대 보안 엔진 및 자체 방어 감도 슬라이더
   - Zero-Recon 허위 프로토콜 가짜 응답 템플릿 커스텀

---

## 6. 실행 및 검증 절차

1. **프로젝트 생성**: `C:\Users\angel\GCAD` 디렉터리에 상기 모든 파일과 코드를 생성.
2. **형식 검증 및 TDD 실행**:
   - `Dafny.exe verify formal/invariants.dfy`를 실행하고 종료 코드 0, `0 errors`를 보존한다. 2026-09-14 기준 모델은 19개 검증 항목, 0개 오류다. 이 결과의 범위는 모델에 한정된다.
   - 퍼징 검증은 실제 로컬 퍼저 또는 테스트 하네스가 존재할 때만 실행한다. `prova-mcp` 결과만으로 퍼징 횟수·0-크래시를 주장하지 않는다.
3. **빌드 검증**:
   ```powershell
   cd C:\Users\angel\GCAD
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build --config Release
   ```
4. **테스트 검증**:
   ```powershell
   .\build\tests\Release\gcad_test.exe (또는 ctest)
   ```
   - 실행된 테스트의 총수·성공·실패를 그대로 기록한다. 실행하지 않은 플랫폼·권한·GUI 시나리오는 미검증으로 남긴다.
5. **실행 확인**:
   ```powershell
   .\build\Release\GCAD.exe --check
   ```
   - 실제 실행 파일 경로와 출력이 현재 빌드 구성과 일치할 때만 정상 초기화·엔진 로드 상태를 확인한다.
6. **보고서 작성**:
   - 모든 작업 완료 후 `C:\Users\angel\GCAD\README.md` 및 `ARCHITECTURE.md`에 시스템 구조, 형식 검증 결과, 빌드 가이드를 최종 기록.

---

**상기 지침에 따라 5대 MCP 도구를 적극 활용하여 독자 설계된 보안 엔진과 완벽한 다크 테마 GUI를 갖춘 완성형 GCAD 프로그램을 구현하십시오.**
```
