import React from 'react'

import { Helmet } from 'react-helmet'

import './login.css'

const Login = (props) => {
  return (
    <div className="login-container">
      <Helmet>
        <title>Login - Far Off Popular Locust</title>
        <meta property="og:title" content="Login - Far Off Popular Locust" />
      </Helmet>
      <div className="login-container1">
        <div className="login-feature-card">
          <h2 className="login-text">Log in</h2>
          <div className="login-container2">
            <h1 className="login-text1">
              <span>Email</span>
              <br></br>
            </h1>
            <input
              type="text"
              placeholder="example.email@gmail.com"
              className="login-textinput input"
            />
          </div>
          <div className="login-container3">
            <h1 className="login-text4">Password</h1>
            <input
              type="text"
              placeholder="Enter at least 8+ characters"
              className="login-textinput1 input"
            />
          </div>
          <div className="login-container4">
            <input
              type="checkbox"
              checked="true"
              required="true"
              className="login-checkbox"
            />
            <span className="login-text5">Remember me</span>
            <a
              href="https://example.com"
              target="_blank"
              rel="noreferrer noopener"
              className="login-link"
            >
              <span>Forgot Password?</span>
              <br></br>
            </a>
          </div>
          <button type="button" className="login-button button">
            Sign in
          </button>
          <span className="login-text8">or Sign in with</span>
          <div className="login-container5">
            <button type="button" className="login-button1 button">
              <svg viewBox="0 0 860.0137142857142 1024" className="login-icon">
                <path d="M438.857 449.143h414.286c4 22.286 6.857 44 6.857 73.143 0 250.286-168 428.571-421.143 428.571-242.857 0-438.857-196-438.857-438.857s196-438.857 438.857-438.857c118.286 0 217.714 43.429 294.286 114.857l-119.429 114.857c-32.571-31.429-89.714-68-174.857-68-149.714 0-272 124-272 277.143s122.286 277.143 272 277.143c173.714 0 238.857-124.571 249.143-189.143h-249.143v-150.857z"></path>
              </svg>
            </button>
            <button type="button" className="login-button2 button">
              <svg viewBox="0 0 877.7142857142857 1024" className="login-icon2">
                <path d="M713.143 73.143c90.857 0 164.571 73.714 164.571 164.571v548.571c0 90.857-73.714 164.571-164.571 164.571h-107.429v-340h113.714l17.143-132.571h-130.857v-84.571c0-38.286 10.286-64 65.714-64l69.714-0.571v-118.286c-12-1.714-53.714-5.143-101.714-5.143-101.143 0-170.857 61.714-170.857 174.857v97.714h-114.286v132.571h114.286v340h-304c-90.857 0-164.571-73.714-164.571-164.571v-548.571c0-90.857 73.714-164.571 164.571-164.571h548.571z"></path>
              </svg>
            </button>
            <button type="button" className="login-button3 button">
              <svg viewBox="0 0 796.0137142857142 1024" className="login-icon4">
                <path d="M796 694.286c-14.286 45.143-37.143 93.143-70.286 142.857-49.143 74.857-98.286 112-146.857 112-19.429 0-45.714-6.286-80-18.286-33.714-12.571-62.857-18.286-86.286-18.286-22.857 0-50.286 6.286-81.143 18.857-31.429 13.143-56.571 19.429-75.429 19.429-58.857 0-115.429-49.714-172-148-55.429-98.286-84-193.714-84-287.429 0-87.429 21.714-158.286 64.571-213.714 42.857-54.857 96.571-82.286 162.286-82.286 28 0 61.143 5.714 101.143 17.143 39.429 11.429 65.714 17.143 78.857 17.143 16.571 0 44-6.286 81.714-19.429 37.714-12.571 70.857-19.429 98.857-19.429 45.714 0 86.286 12.571 121.714 37.143 20 13.714 40 33.143 59.429 57.143-29.714 25.143-51.429 47.429-65.143 67.429-24.571 35.429-37.143 74.857-37.143 118.286 0 46.857 13.143 89.714 39.429 127.429s56.571 61.714 90.286 72zM581.143 24c0 23.429-5.714 49.714-16.571 77.714-11.429 28.571-29.143 54.857-53.143 78.857-20.571 20.571-41.143 34.286-61.714 41.143-13.143 4-32.571 7.429-59.429 9.714 1.143-56.571 16-105.714 44.571-146.857s76.571-69.143 142.857-84.571c1.143 5.143 2.286 9.143 2.857 12.571 0 4 0.571 7.429 0.571 11.429z"></path>
              </svg>
            </button>
          </div>
        </div>
        <div className="login-gallery-card">
          <img alt="image" src="/image%209-1500h.png" className="login-image" />
        </div>
      </div>
    </div>
  )
}

export default Login
