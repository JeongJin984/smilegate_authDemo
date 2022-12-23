import Head from 'next/head'
import Image from 'next/image'
import styles from '../styles/Home.module.css'
import {useEffect, useState} from "react";
import {Button, Form} from "react-bootstrap";
import axios from "axios";
import {useCookies} from "react-cookie";
import { useRouter } from 'next/router'

axios.defaults.withCredentials = true

export default function Home() {
  const router = useRouter()
  const [cookies, setCookie] = useCookies();
  const [username, setUsername] = useState("")
  const [message, setMessage] = useState("")
  const [password, setPassword] = useState("")
  const [passwordCheck, setPasswordCheck] = useState("")

  useEffect(() => {
    /*
    console.log(cookies)
    if(cookies.platform) {
      axios.defaults.withCredentials = true

      axios({
        method: "get",
        url: "http://localhost:8082/"
      }).then(response => {
        alert(response.data)
        setUsername("success")
      })
    }
    */
  }, [cookies])

  const onSubmitLogin = (e) => {
    e.preventDefault()

    let bodyFormData = new FormData()
    bodyFormData.append("username", e.target.querySelector("#formBasicUsername").value)
    bodyFormData.append("password", e.target.querySelector("#formBasicPassword").value)

    axios.defaults.withCredentials = true

    axios({
      method: "post",
      url: "http://localhost:8081/login/jwt/",
      data: bodyFormData
    }).then(response => {
      alert(response.data)
      setUsername("success")
    })
  }

  const onClickKeyCloack = (e) => {
    router.push("http://localhost:8081/login/oauth2/keycloack/")
  }

  const onClickHello = (e) => {
    axios({
      method: "get",
      url: "http://localhost:8082/"
    }).then(response => {
      alert(response.data)
      setMessage(response.data)
    })
  }

  const onChangePassword = (e) => {
    console.log(e.target.value);
    setPassword(e.target.value)
  }

  const onChangePasswordCheck = (e) => {
    console.log(e.target.value);
    setPasswordCheck(e.target.value)
  }

  const onSubmitSignup = (e) => {
    e.preventDefault()
    if(password !== passwordCheck) {
      alert("비밀번호가 일치하지 않습니다.")
    } else {
      axios({
        method: "post",
        url: "http://localhost:8081/signup/",
        data: {
          username: e.target.querySelector("#formSigninUsername").value,
          password: password
        }
      })
    }
  }

  const onClickLogout = (e) => {

  }

  return (
    <div className={styles.container}>
      {
        username ?
          message ? 
          <div>
            {message}
            <Button onClick={onClickLogout}>LogOut</Button>
          </div> :
          <Button onClick={onClickHello}>Hello</Button>:
          <div>
            <Form onSubmit={onSubmitLogin}>
              <Form.Group className="mb-3" controlId="formBasicUsername">
                <Form.Label>Email Username</Form.Label>
                <Form.Control type="text" placeholder="Enter username" />
                <Form.Text className="text-muted">
                  We'll never share your email with anyone else.
                </Form.Text>
              </Form.Group>
              <Form.Group className="mb-3" controlId="formBasicPassword">
                <Form.Label>Password</Form.Label>
                <Form.Control type="password" placeholder="Password" />
              </Form.Group>
              <Button variant="primary" type="submit">
                Submit
              </Button>
            </Form>
            <Button onClick={onClickKeyCloack}>KeyCloack</Button>
            <hr/>
            <Form onSubmit={onSubmitSignup}>
              <Form.Group className="mb-3" controlId="formSigninUsername">
                <Form.Label>Username</Form.Label>
                <Form.Control type="text" placeholder="Enter Username" />
                <Form.Text className="text-muted">
                  We'll never share your email with anyone else.
                </Form.Text>
              </Form.Group>
              <Form.Group className="mb-3" controlId="formSigninPassword">
                <Form.Label>Password</Form.Label>
                <Form.Control onChange={onChangePassword} value={password} type="password" placeholder="비밀번호" />
              </Form.Group>
              <Form.Group className="mb-3" controlId="formSigninPasswordCheck">
                <Form.Label>Password</Form.Label>
                <Form.Control onChange={onChangePasswordCheck} value={passwordCheck} isInvalid={password !== passwordCheck} type="password" placeholder="비밀번호 확인" />
              </Form.Group>
              <Button variant="primary" type="submit">
                회원가입
              </Button>
            </Form>
          </div>
      }
    </div>
  )
}
