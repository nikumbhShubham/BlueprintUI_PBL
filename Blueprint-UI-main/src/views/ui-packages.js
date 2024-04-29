import React from 'react'

import { Helmet } from 'react-helmet'

import UiComponentPackage from '../components/ui-component-package'
import Footer from '../components/footer'
import './ui-packages.css'

const UIPackages = (props) => {
  return (
    <div className="ui-packages-container">
      <Helmet>
        <title>UI-packages - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="UI-packages - Far Off Popular Locust"
        />
      </Helmet>
      <div className="ui-packages-features">
        <div className="ui-packages-pricing">
          <div className="ui-packages-container1">
            <div className="ui-packages-pricing-card">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="ui-packages-image"
              />
            </div>
            <div className="ui-packages-pricing-card1">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="ui-packages-image1"
              />
            </div>
            <div className="ui-packages-pricing-card2">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="ui-packages-image2"
              />
            </div>
          </div>
        </div>
      </div>
      <span className="ui-packages-text">
        <span>
          React Awesome UI is a comprehensive library of beautifully designed
          and customizable
        </span>
        <br></br>
        <span>
          {' '}
          React components, crafted to enhance the user interface and user
          experience of your
          <span
            dangerouslySetInnerHTML={{
              __html: ' ',
            }}
          />
        </span>
        <br></br>
        <span>
          web applications. With a focus on simplicity and performance, each
          component is
          <span
            dangerouslySetInnerHTML={{
              __html: ' ',
            }}
          />
        </span>
        <br></br>
        <span>
          carefully built to be easily integrated into your project, saving you
          time and effort in
          <span
            dangerouslySetInnerHTML={{
              __html: ' ',
            }}
          />
        </span>
        <br></br>
        <span>designing and implementing common UI elements.</span>
      </span>
      <div className="ui-packages-container2">
        <div className="ui-packages-container3">
          <button type="button" className="ui-packages-button button">
            Demo UI
          </button>
          <button type="button" className="ui-packages-button1 button">
            Components
          </button>
          <button type="button" className="ui-packages-button2 button">
            Examples
          </button>
          <button type="button" className="ui-packages-button3 button">
            Package
          </button>
        </div>
      </div>
      <UiComponentPackage rootClassName="ui-component-package-root-class-name"></UiComponentPackage>
      <span className="ui-packages-text10">Floating Button</span>
      <div className="ui-packages-container4">
        <img
          alt="image"
          src="https://play.teleporthq.io/static/svg/default-img.svg"
          className="ui-packages-image3"
        />
        <div className="ui-packages-feature-card">
          <label className="ui-packages-text11">
            <span>Html</span>
            <br></br>
          </label>
          <h2 className="ui-packages-text14">
            <span>&lt;body&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;h1&gt;Welcome to Our Website&lt;/h1&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;/header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;nav&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;</span>
            <span>All rights reserved.</span>
            <br></br>
            <br></br>
            <span> &lt;/footer&gt;</span>
            <br></br>
            <br></br>
            <span>&lt;/body&gt;</span>
            <br></br>
            <br></br>
          </h2>
        </div>
      </div>
      <div className="ui-packages-container5">
        <div className="ui-packages-feature-card1">
          <label className="ui-packages-text40">
            <span>Css</span>
            <br></br>
          </label>
          <h2 className="ui-packages-text43">
            <span>&lt;body&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;h1&gt;Welcome to Our Website&lt;/h1&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;/header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;nav&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;</span>
            <span>All rights reserved.</span>
            <br></br>
            <br></br>
            <span> &lt;/footer&gt;</span>
            <br></br>
            <br></br>
            <span>&lt;/body&gt;</span>
            <br></br>
            <br></br>
          </h2>
        </div>
        <div className="ui-packages-feature-card2">
          <label className="ui-packages-text69">
            <span>Js</span>
            <br></br>
          </label>
          <h2 className="ui-packages-text72">
            <span>&lt;body&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;h1&gt;Welcome to Our Website&lt;/h1&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;/header&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;nav&gt;</span>
            <br></br>
            <br></br>
            <span> &lt;</span>
            <span>All rights reserved.</span>
            <br></br>
            <br></br>
            <span> &lt;/footer&gt;</span>
            <br></br>
            <br></br>
            <span>&lt;/body&gt;</span>
            <br></br>
            <br></br>
          </h2>
        </div>
      </div>
      <Footer rootClassName="footer-root-class-name4"></Footer>
    </div>
  )
}

export default UIPackages
