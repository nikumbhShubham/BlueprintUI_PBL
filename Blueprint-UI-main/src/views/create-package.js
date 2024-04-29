import React from 'react'

import { Helmet } from 'react-helmet'

import Footer from '../components/footer'
import './create-package.css'

const CreatePackage = (props) => {
  return (
    <div className="create-package-container">
      <Helmet>
        <title>create-package - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="create-package - Far Off Popular Locust"
        />
      </Helmet>
      <span className="create-package-text">Create Package</span>
      <div className="create-package-container01">
        <input
          type="text"
          placeholder="Title of Theme"
          className="create-package-textinput input"
        />
        <input
          type="text"
          placeholder="Description"
          className="create-package-textinput1 input"
        />
        <div className="create-package-container02">
          <div className="create-package-container03">
            <div className="create-package-container04">
              <input
                type="text"
                placeholder="Title of Component"
                className="create-package-textinput2 input"
              />
              <div
                data-thq="thq-dropdown"
                className="create-package-thq-dropdown list-item"
              >
                <div
                  data-thq="thq-dropdown-toggle"
                  className="create-package-dropdown-toggle"
                >
                  <span className="create-package-text001">
                    <span>Select Framework</span>
                    <br></br>
                  </span>
                  <div
                    data-thq="thq-dropdown-arrow"
                    className="create-package-dropdown-arrow"
                  >
                    <svg
                      viewBox="0 0 1024 1024"
                      className="create-package-icon"
                    >
                      <path d="M426 726v-428l214 214z"></path>
                    </svg>
                  </div>
                </div>
                <ul
                  data-thq="thq-dropdown-list"
                  className="create-package-dropdown-list"
                >
                  <li
                    data-thq="thq-dropdown"
                    className="create-package-dropdown list-item"
                  >
                    <div
                      data-thq="thq-dropdown-toggle"
                      className="create-package-dropdown-toggle1"
                    >
                      <span className="create-package-text004">
                        <span>React</span>
                        <br></br>
                      </span>
                    </div>
                  </li>
                  <li
                    data-thq="thq-dropdown"
                    className="create-package-dropdown1 list-item"
                  >
                    <div
                      data-thq="thq-dropdown-toggle"
                      className="create-package-dropdown-toggle2"
                    >
                      <span className="create-package-text007">
                        <span>Django</span>
                        <br></br>
                      </span>
                    </div>
                  </li>
                  <li
                    data-thq="thq-dropdown"
                    className="create-package-dropdown2 list-item"
                  >
                    <div
                      data-thq="thq-dropdown-toggle"
                      className="create-package-dropdown-toggle3"
                    >
                      <span className="create-package-text010">
                        <span>Next.js</span>
                        <br></br>
                      </span>
                    </div>
                  </li>
                  <li
                    data-thq="thq-dropdown"
                    className="create-package-dropdown3 list-item"
                  >
                    <div
                      data-thq="thq-dropdown-toggle"
                      className="create-package-dropdown-toggle4"
                    >
                      <span className="create-package-text013">
                        <span>Angular</span>
                        <br></br>
                      </span>
                    </div>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
        <div className="create-package-container05"></div>
      </div>
      <div className="create-package-container06">
        <img
          alt="image"
          src="https://play.teleporthq.io/static/svg/default-img.svg"
          className="create-package-image"
        />
        <div className="create-package-feature-card">
          <label className="create-package-text016">
            <span>Html</span>
            <br></br>
          </label>
          <h2 className="create-package-text019">
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
      <div className="create-package-container07">
        <div className="create-package-feature-card1">
          <label className="create-package-text045">
            <span>Css</span>
            <br></br>
          </label>
          <h2 className="create-package-text048">
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
        <div className="create-package-feature-card2">
          <label className="create-package-text074">
            <span>Js</span>
            <br></br>
          </label>
          <h2 className="create-package-text077">
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
      <div className="create-package-container08">
        <button type="button" className="create-package-button button">
          <span className="create-package-text103">
            <span>Add Code</span>
            <br></br>
          </span>
        </button>
        <button type="button" className="create-package-button1 button">
          Add to package
        </button>
      </div>
      <span className="create-package-text106">Package</span>
      <div className="create-package-container09">
        <img
          alt="image"
          src="https://play.teleporthq.io/static/svg/default-img.svg"
          className="create-package-image1"
        />
        <div className="create-package-feature-card3">
          <label className="create-package-text107">
            <span>Html</span>
            <br></br>
          </label>
          <h2 className="create-package-text110">
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
      <div className="create-package-container10">
        <div className="create-package-feature-card4">
          <label className="create-package-text136">
            <span>Css</span>
            <br></br>
          </label>
          <h2 className="create-package-text139">
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
        <div className="create-package-feature-card5">
          <label className="create-package-text165">
            <span>Js</span>
            <br></br>
          </label>
          <h2 className="create-package-text168">
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
      <div className="create-package-container11">
        <img
          alt="image"
          src="https://play.teleporthq.io/static/svg/default-img.svg"
          className="create-package-image2"
        />
        <div className="create-package-feature-card6">
          <label className="create-package-text194">
            <span>Html</span>
            <br></br>
          </label>
          <h2 className="create-package-text197">
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
      <div className="create-package-container12">
        <div className="create-package-feature-card7">
          <label className="create-package-text223">
            <span>Css</span>
            <br></br>
          </label>
          <h2 className="create-package-text226">
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
        <div className="create-package-feature-card8">
          <label className="create-package-text252">
            <span>Js</span>
            <br></br>
          </label>
          <h2 className="create-package-text255">
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
      <button type="button" className="create-package-button2 button">
        <span className="create-package-text281">Upload</span>
        <svg viewBox="0 0 1024 1024" className="create-package-icon2">
          <path d="M512 170l342 342-342 342-60-60 238-240h-520v-84h520l-238-240z"></path>
        </svg>
      </button>
      <Footer rootClassName="footer-root-class-name3"></Footer>
    </div>
  )
}

export default CreatePackage
