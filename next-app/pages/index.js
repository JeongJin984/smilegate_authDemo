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

  useEffect(() => {
    console.log(cookies)
    // if(cookies.platform) {
    //   axios.defaults.withCredentials = true

    //   axios({
    //     method: "get",
    //     url: "http://localhost:8080/"
    //   }).then(response => {
    //     alert(response.data)
    //     setUsername("success")
    //   })
    // }
  }, [cookies])

  const onSubmit = (e) => {
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
    const stateArray = new Uint32Array(32);
    crypto.getRandomValues(stateArray);
    const state = Buffer.from(stateArray).toString('base64')
    
    const nonceArray = new Uint32Array(32);
    crypto.getRandomValues(nonceArray);
    const nonce = Buffer.from(nonceArray).toString('base64')

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

  return (
    <div className={styles.container}>
      {
        username ?
          message ? 
          <div>{message}</div> :
          <Button onClick={onClickHello}>Hello</Button>:
          <Form onSubmit={onSubmit}>
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
            <Button variant="primary">
              SignIn
            </Button>
          </Form>
      }
      <Button onClick={onClickKeyCloack}>KeyCloack</Button>
    </div>
  )
}