## HTTP

###  

### 목차

**1. HTTP 정의**

**2. HTTP 메소드 및 응답코드**

**3. HTTP 엑세스 제어**

**4. HTTP 캐싱**

**5. HTTP 컨텐츠 협상**

**6. HTTP 조건부 요청**

**7. HTTP 쿠키**

**8. HTTP 범위 요청**

**9.  HTTP 리다이렉트**



####HTTP(HyperText Transfer Protocol) 정의

---

- 하이퍼미디어 문서 전송하기 위한 **`application Layer Protocol`** 로 **`TCP/IP위에서 작동`**
- 인터넷상에서 데이터를 주고 받기 위한 **`서버/클라이언트 모델`**
- 서버가 요청간에 어떠한 데이터 상태도 유지하지 않는 **`Statless protocol`**
- **`Connectless`** 인 비연결형 프로토콜
  -  장점 : 불특정 다수를 대상으로 하는 서비스에 적합
  -  단점 : 클라이언트의 이전 상태를 알 수 없음(`stateless`) `cookie` 를 이용하여 문제 해결 가능



######application Layer Protocol

![HTTP as an application layer protocol, on top of TCP (transport layer) and IP (network layer) and below the presentation layer.](https://mdn.mozillademos.org/files/13673/HTTP%20&%20layers.png)  

> TCP 혹은 암호화된 TCP 연결인 TLS를 통해 전송이 가능하다



#### HTTP 메소드 및 응답코드

---



###### 1. 메소드

| 메소드    | 설명                                                         |
| --------- | ------------------------------------------------------------ |
| `GET`     | 특정 리소스의 표시를 요청                                    |
| `HEAD`    | `GET`과 동일한 응답을 요구하나 본문을 포함하지 않음(헤더만 요청) |
| `POST`    | 특정 리소스에 엔티티를 제출할 때 쓰임                        |
| `PUT`     | 목적 리소스 모든 표시를 요청 `payload`로 바꿈                |
| `DELETE`  | 특정 리소스 삭제                                             |
| `CONNECT` | 목적 리소스로 식별되는 서버로 터널을 맺음                    |
| `OPTIONS` | 목적 리소스의 통신 설정                                      |
| `TRACE`   | 목적 리소스의 경로를 따라 메시지 `loop-back` 테스트          |
| `PATCH`   | 리소스 일정 부분만 수정                                      |

> RESTful 서버의 경우 메소드 구분으로 자원의 위치와 더불어 자원이 할 일을 명시할 수 있어 다양한 메소드를 사용한다.



###### 2. 응답코드

| 코드 | 결과                            | 설명                                                         |
| ---- | ------------------------------- | ------------------------------------------------------------ |
| 100  | Continue                        | 요청을 받았으며 현재 처리중                                  |
| 101  | Switching Protocols             | 클라이언트가 `Upgrade` 헤더를 통해 요청한 것에 따라<br /> 서버가 프로토콜을 바꾼다는 것을 알려주는 응답 코드<br />WebSockets와 함께 사용 |
| 200  | OK                              | 성공적으로 처리                                              |
| 204  | No Content                      | 성공적으로 처리했지만 컨텐츠 제공 안함                       |
| 206  | Partial Content                 | 컨텐츠의 일부 부분만 제공                                    |
| 301  | Moved Permanently               | 영구적으로 컨텐츠가 이동했을 때 사용                         |
| 302  | Found                           | 일시적으로 컨텐츠가 이동했을때 사용                          |
| 303  | See Other                       | 서버가 사용자의 GET요청을 처리하여 다른URL에서<br /> 요청된 정보를 가져올수 있도록 응답하는 코드 |
| 304  | Not Modified                    | 요청된 리소스를 재전송할 필요가 없음                         |
| 400  | Bad Request                     | 요청 자체가 잘못되었을때 사용하는 코드                       |
| 403  | Forbidden                       | 서버가 요청을 거부할 때 발생<br /> 관리자가 해당 사용자를 차단했거나 서버에 index.html 이 없는 경우에도 발생 |
| 404  | Not Found                       | 찾는 리소스가 없다는 뜻                                      |
| 405  | Method Not Allowed              | PUT이나 DELETE 등 서버에서 허용되지 않은 메소드로 요청시 사용하는 코드 |
| 406  | Not Acceptable                  | 요청은 정상이나 서버에서 받아들일 수 없는 요청일시 사용하는 코드<br />웹 방화벽에 걸리는 경우 이 코드가 반환 |
| 500  | Internal Server Error           | 서버에 오류가 발생해 작업을 수행할 수 없을 때 사용           |
| 502  | Bad Gateway                     | 게이트웨이가 연결된 서버로부터 잘못된 응답을 받았을 때 사용  |
| 503  | Service Temporarily Unavailable | 서비스를 일시적으로 사용할 수 없을 때 사용된다. <br />주로 웹서버 등이 과부하로 다운되었을 때 볼 수 있다. |
| 504  | Gateway Timeout                 | 게이트웨이가 연결된 서버로부터 응답을 받을 수 없었을 때 사용 |



#### HTTP 헤더

---

###### 1. RequestHeader

**`Age`** : 개체가 프록시 캐시에 있었던 시간

**`Allow`** : 자원이 지원하는 메소드 세트 나열

**`Alt-Svc`** : 해당 웹사이트에 접근할 수 있는 대체 방법 나열 

- Syntax

  ```
  Alt-Svc: clear
  Alt-Svc: <protocol-id>=<alt-authority>; ma=<max-age>
  Alt-Svc: <protocol-id>=<alt-authority>; ma=<max-age>; persist=1
  ```

  - `<clear>` : 무효화 요청
  - `<protocol-id>` : 프로토콜 식별자 (h2 = HTTP/2, h3 = HTTP/3)
  - `<alt-authority>` : 선택적 호스트 대체, 콜론 및 필수 포트 번호
  - `ma=<max-age>` : 응답 기간을 제외한 *최대 * 초 동안 캐시
  - `persist=1` : 일반적으로 캐시 된 대체 서비스 항목은 네트워크 구성 변경시 지워진다. persist = 1 매개 변수를 사용하면 해당 변경 사항을 통해 항목이 삭제되지 않음.

- EX

  ```
  Alt-Svc: h2=":443"; ma=2592000;
  Alt-Svc: h2=":443"; ma=2592000; persist=1
  Alt-Svc: h2="alt.example.com:443", h2=":443"
  Alt-Svc: h3-25=":443"; ma=3600, h2=":443"; ma=3600
  ```

  

**`User-Agent`** : 



#### HTTP 엑세스 제어(CORS) 및 인증

---

######1-1. CORS(Cross-Origin Resource Sharing) 정의

**웹 페이지의 JavaScript가 AJAX요청을 원래 도메인과 다른 도메인에 요청하도록 하는 메커니즘**



###### 1-2. CORS 동작 과정

- 실제 요청하려는 경로와 같은 URL에 대해 OPTIONS로 요청을 날려보고 요청가능한지 확인

- 실제 요청 전송

![Alt CORS 동작과정](https://heowc.dev/resources/img/spring-boot-cors/cors_flow-49c352bc6c3c8ae7dc5934837661aff4.jpg) 

> `pre-flight` : 실제 요청하려는 경로와 같은 URL에 대해 OPTIONS로 요청을 날려보고 요청가능한지 확인



| 속성               | 기술                                                         |
| ------------------ | ------------------------------------------------------------ |
| `origins`          | 허용 된 출발지 목록. 이 값은 `Access-Control-Allow-Origin` 는 `pre-flight` 전 응답과 실제 응답 의 헤더에 배치됩니다 . |
| `allowedHeaders`   | 실제 요청 중에 사용할 수있는 요청 헤더 목록. `pre-flight`의 응답 헤더에 값이 사용됩니다 `Access-Control-Allow-Headers`. |
| `methods`          | 지원되는 HTTP 요청 방법 목록 정의되지 않은 경우 `RequestMapping`주석으로 정의 된 메소드 가 사용됩니다. |
| `exposedHeaders`   | 브라우저가 클라이언트가 액세스 할 수 있도록하는 응답 헤더 목록입니다. 실제 응답 헤더에 값이 설정됩니다 `Access-Control-Expose-Headers`.경우 *정의되지 않은* 빈 노출 헤더 목록이 사용됩니다. |
| `allowCredentials` | 브라우저가 요청과 관련된 쿠키를 포함해야하는지 여부를 결정합니다.`false` – 쿠키는 포함하지 않아야합니다.`" "`(빈 문자열) – *undefined를* 의미 합니다.`true`– `pre-flight` 전 응답에는 `Access-Control-Allow-Credentials`값이 true로 설정된 헤더가 포함. |
| `maxAge`           | `pre-flight` 전 응답에 대한 캐시 기간의 최대 수명 (초). 헤더에 값이 설정되어 `Access-Control-Max-Age`있습니다. |



###### 1-3. Spring CORS 예제

**Method Level**

```java
@Controller
public class HomeController 
{
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    @GetMapping(path="/")
    public String homeInit(Model model) {
        return "home";
    }
}
```

> `@CrossOrigin` 은 default로 모든 출처, 헤더, 메소드에대해 `maxAge` 30분 동한 허용. 



**Global Level (WebMvcConfigurer bean)**

```java
@Configuration
public class CorsConfiguration 
{
    @Bean
    public WebMvcConfigurer corsConfigurer() 
    {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("http://localhost:8080");
            }
        };
    }
}
```



**CORS with Spring Security**

```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
            //other config
    }
 
    @Bean
    CorsConfigurationSource corsConfigurationSource() 
    {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```



###### 2-1 HTTP 기본인증(Basic authentication)

![img](http://iloveulhj.github.io/images/basic-auth/basic-auth2.png) 

| 단계      | 헤더               | 설명                                                         | 메서드/상태 |
| --------- | ------------------ | ------------------------------------------------------------ | ----------- |
| 요청      |                    | 첫번째 요청 인증 정보가 없음                                 | GET         |
| 인증 요구 | WWW-Authenticate   | 서버에서 사용자 이름과 비밀번호를 제공하라는 의미로<br /> 401 반환과 함께 요청을 반려 | 401         |
| 인증      | Authorization      | 클라이언트에서 인증 알고리즘과 <br />사용자 이름, 비밀번호를 기술한 Authorization헤더를 재 요청 | GET         |
| 성공      | Authorization-Info | 인증 정보가 정확하다면 성공 응답<br />(Authorization-Info에 인증 세션에 관한 추가 정보 기술 가능) | 200         |



#### HTTP 캐싱(caching)

---

**이전에 가져온 리소스를 재사용하여 대기시간과 네트워크 트래픽을 줄이고 리소스 표현을 표시하는 데 필요한 시간을 줄여 웹사이트의 응답성을 향상된다.**

###### 1. 캐시의 종류

- **`No cache`** : 캐시를 사용하지 않음
- **`Local(private) cache`** : 개인 브라우저 캐시, 캐시 된 컨텐츠의 오프라인 브라우징 향상
- **`shered cache`** : 공유 프록시 캐시, 둘 이상의 사용자가 재사용 할 응답을 저장하는 캐시



###### 2. 캐싱 제어 

- `no-store` = 캐시 사용 안함, 요청 서버에서 매번 전체 응답 다운

- `no-cache` = 캐시는 사용하나 재확인, 사본을 release 하기전에 origin 서버로 유효성 검증(http1.0=`pragma`)

- `must-revalidate` = 만료된 캐시만 서버에 검증 요청

- `private` = 개인 브라우저 캐시에만 응답을 저장

- `public` = 일반적으로 캐시 할 수 없는 HTTP인증 또는 응답 상태 코드가 있는 페이지를 캐시하는 경우 유용

- `max-age=<seconds>` = resource 유효 최대 시간(만료 시간 지정)

  ```http
  Cache-Control: max-age=31536000
  ```

- **`ETag`** = 캐시에 대한 유효성 검사 수행

 ![HTTP Cache-Control 예시](https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/images/http-cache-control.png?hl=ko) 

> 응답이 만료된 시점에 새 요청시 응답에서 리소스 전체를 새로 받아오지만, `ETag` 를 사용해 변경된 사항이 없는 동일한 리소스의 경우 304(Not Modified)를 반환된다. 다시 다운로드할 필요가 없으므로 시간과 대역폭이 절약 된다. 



###### 3. 조건부 요청

![캐시가 비어있을 때 발행 된 요청은 유효성 검사기 값이 모두 헤더로 전송되어 다운로드 할 리소스를 트리거합니다.  그런 다음 캐시가 채워집니다.](https://mdn.mozillademos.org/files/13729/Cache1.png) 

> 클라이언트가 리소스 요청시 리소스와 함께 유효성 검사를 위한 `Last-Modified` 와 `Etag` 가 전송



![오래된 캐시를 사용하면 조건부 요청이 전송됩니다.  서버는 자원이 변경되었는지 판별 할 수 있으며,이 경우와 동일하므로 다시 보내지 않기로 결정합니다.](https://mdn.mozillademos.org/files/13731/HTTPCache2.png) 

> 캐시가 오래되면 `Cache-Control` 헤더에 의해 제어되고, 조건부 요청을 발행해 `If-Modified-Since` ,  `If-Match` 헤더의 매개변수로 사용

> 자원이 변경되지 않은 경우 `304 Not Modified` 응답



![리소스가 변경된 경우 요청이 조건이없는 것처럼 다시 전송됩니다.](https://mdn.mozillademos.org/files/13733/HTTPCache3.png) 

> 자원이 변경 된 경우 새 버전의 자원과 유효성 검사기 응답 `200 OK`



| 헤더                      | 설명                                                         |
| :------------------------ | ------------------------------------------------------------ |
| **`If-Match`**            | `ETag`원격 자원이 이 헤더에 나열된 것과 같으면 성공합니다 . 기본적으로 etag 앞에 접두사가 없으면 `'W/'`강력한 유효성 검사를 수행합니다. |
| **`If-None-Match`**       | `ETag`원격 자원이이 헤더에 나열된 것과 다를 경우 성공합니다 . 기본적으로 etag 앞에 접두사가 없으면 `'W/'`강력한 유효성 검사를 수행합니다. |
| **`If-Modified-Since`**   | `Last-Modified`원격 자원 의 날짜가이 헤더에 제공된 날짜보다 최신 인 경우에 성공합니다 . |
| **`If-Unmodified-Since`** | `Last-Modified`원격 자원 의 날짜가이 헤더에 제공된 날짜보다 오래되었거나 같은 경우에 성공합니다 . |
| **`If-Range`**            | 유사 `If-Match`하거나 `If-Unmodified-Since`, 오직 하나의 ETAG, 또는 하나의 일을 할 수 있습니다. 실패하면 범위 요청이 실패하고 응답 대신 전체 리소스와 함께 a 가 전송됩니다. |



#### 간단한 Springboot Cache 적용

###### 1. dependencies

```java
compile('org.springframework.boot:spring-boot-starter-cache')
```



###### 2. cache기능을 사용하고자 하는 프로젝트 실행 클래스에 @EnableCaching 선언

```java
@EnableCaching
@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```



######3. 캐시하고 싶은 메서드에 @Cacheable, 캐시를 제거하고자하는 메서드에는 @CacheEvict 사용

```java
@Service
public class TestService {
    private List<String> list;
    
    @PostConstruct
    public void init() {
        list = new ArrayList<>();
    }
    //value = 캐시 아이디
    @Cacheable(value="test")
    public String getInformation(String info) {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return list.stream().filter(x->x.equals(info)).findFirst().get();
    }
    
    @CacheEvict(value="test")
    public void createInformation(String info) {
        list.add(info);
    }
}
```



####HTTP  컨텐츠 협상(Content Negotiation)

---

**동일한  URL에서 리소스의 서로 다른 버전을 지원하기 위해 사용되는 메커니즘**

1. 클라이언트가 리소스를 내려받기를 원하는 경우, URL을 사용하여 요청한다.

2. 서버는 리소스를 선택하기 위해 URL을 사용하여 클라이언트에게 리소스의 특정 프레젠테이션을 반환한다.

> 프레젠테이션 : 리소스가 제공하는 변형





#### 서버주도 컨텐츠 협상

**헤더 목록인 `Accept`, `Accept-Charset`, `Accept-Encoding`, `Accept-Language` 를 정의**

**어떤 헤더가 사용될 지 가리키기 위해`Vary`헤더 사용**



######Accept

**클라이언트가 처리하고자 하는 파일 형식(MIME TYPE)을 나열한 헤더**

`*/*`  = 모든 MIME 유형

`<MIME_type>/*` = 하위 유형 없음 (ex: `image/*`(`image/png`, `image/svg`, `image/gif`))

`<MIME_type>/<MIME_subtype>` = 정확한 MIME 타입 지정 (ex: `text/html`)

`;q=` = 상대 품질 계수 (0 ~ 1)

```http
Request Headers
//default
Accept: */*
// Default for navigation requests
Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8
Accept: text/html
Accept: image/*
```



######Accept-Charset

**클라이언트가 어떤 종류의 인코딩을 이해 할 수 있는지 알려주는 헤더**

> 현재는 UTF-8이 보편화 되어 위 헤더를 생략



###### Accept-Encoding

**클라이언트가 압축 가능한 컨텐츠 인코딩을 정의한 헤더**

>  jpeg 이미지와 같은 어떤 유형의 리소스들은 이미 압축되어 있으며 추가적인 압축은 페이로드를 더 길게 만들수도 있다

```http
Request Headers
Accept-Encoding: gzip
Accept-Encoding: br
Accept-Encoding: *
//Multiple algorithms, weighted with the quality value syntax
Accept-Encoding: deflate, gzip;q=1.0, *;q=0.5
```



![img](https://mdn.mozillademos.org/files/13811/HTTPCompression1.png) 



######Accept-Lenguage

**클라이언트가 선호하는 언어를 가리키는 헤더**

```http
Request Headers
Accept-Language: en-US,en;q=0.5
```



###### Very

**캐시 된 응답을 향후 요청시 새로운 요청 대신 사용 할 수 있는지 여부를 결정하는 헤더**

```http
Request Headers
//캐시할 수 없는 요청 간주(Cache-Control헤더를 사용하는게 더 명시적이다.)
Vary: *
//지정된 헤더만 캐시된 응답을 사용할 수 있도록 결정
Vary: <header-name>, <header-name>, ...
Vary: User-Agent
```

> 서버는 자신이 캐쉬한 응답을 적절한 Accept-Encoding 요청 헤더를 보낸 클라이언트에게만 보내도록 Vary: Accept-Encoding으로 설정



####HTTP 압축(Compresstion)

---

**HTTP 압축은 웹 사이트의 성능을 높이는 중요한 방법. **

**어떤 문서에 대해, 70%가 넘는 사이즈 축소는 필요로 하는 대역폭 용량을 낮춰준다**





#####WWW(World Wide Web)

- 인터넷상의 정보를 하이퍼텍스트 방식과 멀티미디어 환경에서 검색할 수 있게 해주는 정보 검색 시스템



#####하이퍼텍스트(HyperText)

- 웹 브라우저라는 프로그램을 통해 웹 서버에서 문서나, 웹페이지 등의 정보 조각을 읽어들여 모니터에 출력하게 하게 된다.



https://chorizzori.tistory.com/79

