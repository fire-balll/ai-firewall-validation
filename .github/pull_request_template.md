## 무엇을 했나

<!-- 한두 문장. 관련 이슈가 있으면 #번호 -->

## 왜

<!-- 공유 문서의 어느 항목과 관련되는지 -->

## 어떻게 확인했나

- [ ] `python3 -m py_compile $(git ls-files '*.py')`
- [ ] `bash -n lab/*.sh pipeline/*.sh`
- [ ] mock 생성 → validator 통과
- [ ] `python3 -m unittest discover -s tests -t .`
- [ ] 랩에서 `check-path.sh` / `pipeline/run.sh` (실행하지 않았으면 체크하지 말고 이유를 적기)
- [ ] 외부 의존(컨테이너·명령·파일)을 바꿨다면, 그 대상을 멈춘 상태에서 결과 대신 실패가 나는지 (AGENTS.md 핵심 원칙. 해당 없으면 "해당 없음")

## 리뷰어가 볼 것

<!-- 다른 담당자 영역을 건드렸거나, schema·의존성을 바꿨으면 여기 적기 -->
