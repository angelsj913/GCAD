# 🛡️ GCAD — 프로젝트 에이전트 지침 및 정밀 디버깅 표준 (Project AGENTS.md)

이 문서는 GCAD(Galoisconnection Antivirus & Defense) 프로젝트에서 코드를 디버깅, 리팩터링, 작성, 검증할 때 항구적으로 자동 적용되는 프로젝트 전용 지침서입니다. 다운로드된 4대 글로벌 디버깅 스킬(`systematic-debugging`, `safe-debug`, `debugging-and-error-recovery`, `debugging-strategies`)의 철칙이 통합 반영되어 있습니다.

---

## 1. 5대 디버깅 철칙 (The Iron Laws of Debugging)

1. **원인 규명 선행의 원칙 (Root Cause Investigation First)**:
   - 증상만 가리는 임시 땜질(Symptom Patching)은 엄격히 금지한다.
   - 모든 결함에 대해 반드시 호출 스택, 락 획득 순서, 메모리 수명 주기, OS API 반환값을 추적하여 근본 원인(Root Cause)을 규명한 후 수정을 진행한다.
2. **무결성 락 안전성 보장 (Zero-Deadlock & Lock Safety Invariant)**:
   - `std::mutex`를 보유한 상태에서 동일 뮤텍스를 요구하는 함수를 중복 호출하지 않는다 (Self-Deadlock 원천 차단).
   - 필요 시 `std::recursive_mutex`를 도입하거나, 반드시 `_unlocked` 접미사가 붙은 내부 전용 프라이빗 헬퍼를 분리한다.
   - 비동기 워커 스레드가 쓰는 컨테이너에 대해 UI 스레드에 날것(Raw)의 레퍼런스를 노출하지 않으며, 반드시 뮤텍스 락 보호 하에 복사본(Snapshot)을 반환한다.
3. **블로킹 없는 I/O 및 DoS 방어 (Non-Blocking & Timeout Invariant)**:
   - 네트워크 소켓 수신 시 블로킹 `recv`로 스레드를 무한 정지시키지 않는다.
   - 모든 클라이언트 소켓에는 `SO_RCVTIMEO` 타임아웃을 강제하거나 논블로킹 모드를 적용하여 악의적 슬로우/침묵 연결(Slowloris) 공격으로부터 시스템을 보호한다.
4. **유령 보안 감시 금지 (Zero-Phantom Invariant)**:
   - 0번지 더미 카나리만 돌리는 유령 엔진이나, API 스펙을 오용하여 무의미한 에러를 내는 자체 방어 코드를 배제한다.
   - 실제 OS 프로세스 메모리, 핸들 테이블, 디스크 이벤트를 정확한 NTAPI/Win32 스펙에 맞춰 실감시하도록 구현한다.
5. **UI 렌더 루프 순수성 유지 (Pure Render Loop / No Side-Effects)**:
   - ImGui 렌더링 함수(`render_*`) 본문에서 슬라이딩 윈도우 인덱스를 회전하거나 내부 상태를 무차별 변조하는 부수효과(Side-Effect)를 유발하지 않는다. 상태 갱신은 이벤트 도착 시점에만 수행한다.

---

## 2. 정밀 디버깅 4단계 실행 프로토콜

- **1단계: 진단 및 코드 역추적 (Trace)**: 버그가 위치한 정확한 파일 경로, 라인 번호, 데이터 흐름 확인.
- **2단계: 최소 단위 안전 패치 (Smallest Working Patch)**: 다른 컴포넌트에 파급 효과를 주지 않는 가장 작고 견고한 C++20 네이티브 코드 패치 적용.
- **3단계: 증거 기반 컴파일 및 테스트 (Evidence Verification)**: CMake 빌드 및 `gcad_tests.exe` 실행으로 컴파일 에러 0건 및 기존/신규 테스트 100% 통과 입증.
- **4단계: 런타임 자체 회고 (Self-Audit)**: 수정된 코드가 메모리 누수, 데드락, 경합 조건을 유발하지 않는지 재검토.

---
