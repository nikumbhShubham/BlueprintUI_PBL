import React from 'react'
import { Link } from 'react-router-dom'

import { Helmet } from 'react-helmet'

import Navbar from '../components/navbar'
import MainFeatures from '../components/main-features'
import HeaderOfAllPublishers from '../components/header-of-all-publishers'
import AllPublishersCard from '../components/all-publishers-card'
import HomepageFooter from '../components/homepage-footer'
import './home.css'

const Home = (props) => {
  return (
    <div className="home-container">
      <Helmet>
        <title>Far Off Popular Locust</title>
        <meta property="og:title" content="Far Off Popular Locust" />
      </Helmet>
      <div className="home-profile">
        <div className="home-container01">
          <div className="home-container02">
            <div className="home-container03"></div>
          </div>
        </div>
        <div className="home-container04">
          <Navbar rootClassName="navbar-root-class-name"></Navbar>
          <div className="home-container05">
            <div className="home-container06">
              <div className="home-container07">
                <div className="home-container08">
                  <div className="home-container09">
                    <div className="home-container10">
                      <span className="home-text">
                        <span className="home-text01">Build fast,</span>
                        <span className="home-text02">responsive</span>
                        <br className="home-text03"></br>
                        <span className="home-text04">
                          {' '}
                          Components
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <br className="home-text05"></br>
                        <span className="home-text06">with</span>
                        <br></br>
                        <span>
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <span className="home-text09">&lt;BlueprintUI&gt;</span>
                        <br className="home-text10"></br>
                        <br></br>
                      </span>
                      <span className="home-text12">
                        <span>
                          Discover a universe of UI excellence at Blueprint.
                          Elevate your
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <br></br>
                        <span>projects with our rich library </span>
                        <span>
                          of meticulously crafted
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <br></br>
                        <span>
                          components.
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <span>From sleek buttons to dynamic modules, our</span>
                        <br></br>
                        <span>
                          {' '}
                          platform
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <span>
                          empowers you to create stunning user interfaces
                          <span
                            dangerouslySetInnerHTML={{
                              __html: ' ',
                            }}
                          />
                        </span>
                        <br></br>
                        <span>
                          effortlessly. Revolutionize your design journey with
                          us.
                        </span>
                      </span>
                    </div>
                  </div>
                  <div className="home-container11">
                    <Link to="/workspace" className="home-navlink button">
                      <span className="home-text25">
                        <span>Get Started</span>
                        <br></br>
                      </span>
                    </Link>
                    <Link to="/component" className="home-navlink1 button">
                      <svg viewBox="0 0 1024 1024" className="home-icon">
                        <path d="M606 606l162-350-350 162-162 350zM512 86q176 0 301 125t125 301-125 301-301 125-301-125-125-301 125-301 301-125zM512 466q20 0 33 13t13 33-13 33-33 13-33-13-13-33 13-33 33-13z"></path>
                      </svg>
                      <span className="home-text28">  Explore Components</span>
                    </Link>
                  </div>
                </div>
              </div>
            </div>
            <img
              alt="image"
              src="/image%2019-600h.png"
              className="home-image"
            />
          </div>
        </div>
        <MainFeatures rootClassName="main-features-root-class-name"></MainFeatures>
      </div>
      <HeaderOfAllPublishers rootClassName="header-of-all-publishers-root-class-name"></HeaderOfAllPublishers>
      <AllPublishersCard rootClassName="all-publishers-card-root-class-name1"></AllPublishersCard>
      <HomepageFooter rootClassName="homepage-footer-root-class-name1"></HomepageFooter>
    </div>
  )
}

export default Home
