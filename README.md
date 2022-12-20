## Introduction

> Spring Security를 이용한 Jwt, OAuth20 기반의 인증, 인가 시스템 구현

![](https://velog.velcdn.com/images/jeongjin984/post/b84aaeb3-5177-4228-91c4-15e75f11668e/image.png)

- 4번 Sequence는 쿠키를 가져오거나 생성한 후에 그 정보를 저장
- JWT의 경우 Auth Server의 "/jwt/valid/" URI를 통해 Access Token을 발급하거나 Invalidate한 Token의 경우 Error를 return 

## Stack

- **BackEnd**: Spring Boot, Spring Security, Spring Data JPA(Hibernate), Http(Resttemplate)
- **DB**: MySQL
- **Chache**: Redis
- **FrontEnd**: React, Next.js, React-Bootstrap, axios
- **OAuth Server**: KeyCloack

## Q&A

- 서비스가 확장해 간다고 할때 API Gateway를 굳이 사용해야 할 상황이 있다면 어떤 것들이 있는까요?
   - 서비스가 확장해 나가면 유저들 간에 관계가 복잡해 짐에 따라 권한 처리도 같이 복잡해 진다고 생각합니다.
   - 이에 따라 권한 체크를 각 서비스에서 하는 것이 하나의 Gateway에서 처리하는 것 보다 좋다고 생각합니다.
   - 공통된 Gateway에서 처리할 경우 단일 Point 문제와 함께 모든 권한 정보를 위해 모든 서비스의 DB를 읽어야 하는 복잡성이 증가된다고 생각하기 때문입니다.
- 서비스의 성능을 측정 할 때 주로 측정되는 지표가 무엇인가요?
- 코드를 잘 작성하는 것이 중요하다고는 하지만 그것이 잘 와닿지 않습니다. 항상 손이 성능과 직접 연결되어 있는 Transaction 관리, 불필요한 IO등의 코드에 갑니다.
