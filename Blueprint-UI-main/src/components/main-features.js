import React from 'react'

import PropTypes from 'prop-types'

import './main-features.css'

const MainFeatures = (props) => {
  return (
    <div className={`main-features-container ${props.rootClassName} `}>
      <h1 className="main-features-text">{props.heading}</h1>
      <div className="main-features-feature-card">
        <div className="main-features-container1">
          <span className="main-features-text01">
            <span className="">
              Kickstart your Tailwind CSS web project using the TaiGrids UI
              component library. Unlock asuite of all esential UlI components
              for the seamless creation of data-rich dashboards,- 
            </span>
            <span className="">
              commerce interfaces, web apps, high-converting landing pages, and
              more all without the 
            </span>
            <span className="">
              hassle of coding or designing from scratch.
            </span>
          </span>
        </div>
      </div>
      <div className="main-features-container2">
        <div className="main-features-feature-card1">
          <svg viewBox="0 0 1024 1024" className="main-features-icon">
            <path
              d="M128 214h810v256h-810v-256zM426 810v-298h512v298h-512zM128 810v-298h256v298h-256z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text05">500+UI Components</h2>
          <span className="main-features-text06">
            <span className="">Beautifully crafted 500+ Taiwind</span>
            <br className=""></br>
            <span className="">Components for HTML, React, and</span>
            <br className=""></br>
            <span className="">Vue components. From buttons to</span>
            <br className=""></br>
            <span className="">testimonials, weve got you covered</span>
          </span>
        </div>
        <div className="main-features-feature-card2">
          <svg viewBox="0 0 1024 1024" className="main-features-icon02">
            <path
              d="M938 296l-130 146q74 118 88 262h-86q-12-102-62-194l-172 194-170-172-256 256-64-64 320-320 170 172 122-140q-118-138-288-138-146 0-264 104l-60-60q144-128 324-128 204 0 346 158l122-136z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text14">Multi-Framework Support</h2>
          <span className="main-features-text15">
            TaiGrids components are now avilable in HTML, React, Vue, and Figma.
            I also allows you to convert the same code for other frameworks
            without rewriting the entire component
          </span>
        </div>
        <div className="main-features-feature-card3">
          <svg
            viewBox="0 0 661.1382857142856 1024"
            className="main-features-icon04"
          >
            <path
              d="M647.429 596c10.857 10.286 13.714 26.286 8 39.429-5.714 13.714-18.857 22.857-33.714 22.857h-218.286l114.857 272c8 18.857-1.143 40-19.429 48l-101.143 42.857c-18.857 8-40-1.143-48-19.429l-109.143-258.286-178.286 178.286c-6.857 6.857-16 10.857-25.714 10.857-4.571 0-9.714-1.143-13.714-2.857-13.714-5.714-22.857-18.857-22.857-33.714v-859.429c0-14.857 9.143-28 22.857-33.714 4-1.714 9.143-2.857 13.714-2.857 9.714 0 18.857 3.429 25.714 10.857z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text16">Easy to Use</h2>
          <span className="main-features-text17">
            Experience the simplicity of our copy-paste interface with no
            complex dependencies. Copy the code snippet and effortlessly paste
            it into your Tailwind project or start a new one.
          </span>
        </div>
        <div className="main-features-feature-card4">
          <svg viewBox="0 0 1024 1024" className="main-features-icon06">
            <path
              d="M152.388 48.522l-34.36 171.926h699.748l-21.884 111.054h-700.188l-33.892 171.898h699.684l-39.018 196.064-282.012 93.422-244.4-93.422 16.728-85.042h-171.898l-40.896 206.352 404.226 154.704 466.006-154.704 153.768-772.252z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text18">Tailwind css</h2>
          <span className="main-features-text19">
            Utilize the latest version of Tailwind CSS for a modern and
            minimalistic design. Ensuring an exceptional experience for
            development, design and coding.
          </span>
        </div>
        <div className="main-features-feature-card5">
          <svg
            viewBox="0 0 877.7142857142857 1024"
            className="main-features-icon08"
          >
            <path
              d="M863.429 603.429c0 1.143 0 2.857-0.571 4-48.571 202.286-215.429 343.429-426.286 343.429-111.429 0-219.429-44-300.571-121.143l-73.714 73.714c-6.857 6.857-16 10.857-25.714 10.857-20 0-36.571-16.571-36.571-36.571v-256c0-20 16.571-36.571 36.571-36.571h256c20 0 36.571 16.571 36.571 36.571 0 9.714-4 18.857-10.857 25.714l-78.286 78.286c53.714 50.286 125.143 78.857 198.857 78.857 101.714 0 196-52.571 249.143-139.429 13.714-22.286 20.571-44 30.286-66.857 2.857-8 8.571-13.143 17.143-13.143h109.714c10.286 0 18.286 8.571 18.286 18.286zM877.714 146.286v256c0 20-16.571 36.571-36.571 36.571h-256c-20 0-36.571-16.571-36.571-36.571 0-9.714 4-18.857 10.857-25.714l78.857-78.857c-54.286-50.286-125.714-78.286-199.429-78.286-101.714 0-196 52.571-249.143 139.429-13.714 22.286-20.571 44-30.286 66.857-2.857 8-8.571 13.143-17.143 13.143h-113.714c-10.286 0-18.286-8.571-18.286-18.286v-4c49.143-202.857 217.714-343.429 428.571-343.429 112 0 221.143 44.571 302.286 121.143l74.286-73.714c6.857-6.857 16-10.857 25.714-10.857 20 0 36.571 16.571 36.571 36.571z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text20">Refreshing Design</h2>
          <span className="main-features-text21">
            Clean, refreshing, and high-quality design to leave a positive
            impression on end-users. TailGrids adheres to modern design trends,
            ensuring a clean and clear visual experience..
          </span>
        </div>
        <div className="main-features-feature-card6">
          <svg viewBox="0 0 1024 1024" className="main-features-icon10">
            <path
              d="M726 810v-84h84v170q0 34-25 60t-59 26h-428q-34 0-59-26t-25-60v-170h84v84h428zM426 648l-60 60-196-196 196-196 60 60-134 136zM658 708l-60-60 134-136-134-136 60-60 196 196zM298 214v84h-84v-170q0-34 25-60t59-26l428 2q34 0 59 25t25 59v170h-84v-84h-428z"
              className=""
            ></path>
          </svg>
          <h2 className="main-features-text22">Developer Friendly</h2>
          <span className="main-features-text23">
            Clean, refreshing, and high-quality design to leave a positive
            impression on end-users. TailGrids adheres to modern design trends,
            ensuring a clean and clear visual experience..
          </span>
        </div>
      </div>
    </div>
  )
}

MainFeatures.defaultProps = {
  heading: 'Main Features',
  rootClassName: '',
}

MainFeatures.propTypes = {
  heading: PropTypes.string,
  rootClassName: PropTypes.string,
}

export default MainFeatures
