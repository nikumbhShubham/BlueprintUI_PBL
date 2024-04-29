import React from 'react'
import { Link } from 'react-router-dom'

import { Helmet } from 'react-helmet'

import Navbar from '../components/navbar'
import Footer from '../components/footer'
import './about-us.css'

const AboutUs = (props) => {
  return (
    <div className="about-us-container">
      <Helmet>
        <title>About-us - Far Off Popular Locust</title>
        <meta property="og:title" content="About-us - Far Off Popular Locust" />
      </Helmet>
      <Navbar rootClassName="navbar-root-class-name2"></Navbar>
      <div className="about-us-hero">
        <div className="about-us-container1">
          <h1 className="about-us-text">
            <span>Let&apos;s keep things </span>
            <br></br>
            <span>organised</span>
            <br></br>
          </h1>
          <span className="about-us-text05">
            BlueprintUI is your go-to destination for streamlined UI
            development. Our platform offers a wide array of UI components and
            code snippets, making it easier than ever for developers to create
            stunning user interfaces. With themed packages, premium components,
            and innovative subscription models, BlueprintUI is dedicated to
            simplifying the web development process while ensuring a seamless
            user experience. Join us and revolutionize the way you build UIs.
          </span>
          <div className="about-us-btn-group">
            <Link to="/workspace" className="about-us-navlink button">
              Get Started
            </Link>
          </div>
        </div>
        <img
          alt="image"
          src="/image%2019-600h.png"
          className="about-us-image"
        />
      </div>
      <div className="about-us-banner">
        <h1 className="about-us-text06">Our Mission</h1>
        <span className="about-us-text07">
          <span className="about-us-text08">
            At BlueprintUI, our mission is to revolutionize UI development by
            providing developers with easy access to a comprehensive library of
            UI components and code snippets. We aim to streamline the web
            development process, empowering developers to create stunning user
            interfaces with efficiency and ease. Through themed packages,
            premium components, and innovative subscription models, we strive to
            make high-quality UI design accessible to all. Our goal is to foster
            creativity, efficiency, and collaboration in the web development
            community while delivering a seamless user experience. Join us as we
            transform the landscape of UI development, one blueprint at a time.
          </span>
          <span>
            <span
              dangerouslySetInnerHTML={{
                __html: ' ',
              }}
            />
          </span>
          <span>
            <span
              dangerouslySetInnerHTML={{
                __html: ' ',
              }}
            />
          </span>
        </span>
      </div>
      <Footer rootClassName="footer-root-class-name5"></Footer>
    </div>
  )
}

export default AboutUs
