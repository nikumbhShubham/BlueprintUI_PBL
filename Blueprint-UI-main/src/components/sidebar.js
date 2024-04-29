import React from 'react'
import { Link } from 'react-router-dom'

import PropTypes from 'prop-types'

import './sidebar.css'

const Sidebar = (props) => {
  return (
    <div className={`sidebar-sidebar ${props.rootClassName} `}>
      <div className="sidebar-container">
        <Link to="/profile-page" className="sidebar-navlink">
          <div className="sidebar-container1">
            <svg viewBox="0 0 1024 1024" className="sidebar-icon">
              <path
                d="M384 736c0-151.234 95.874-280.486 230.032-330.2 16.28-36.538 25.968-77.164 25.968-117.8 0-159.058 0-288-192-288s-192 128.942-192 288c0 99.060 57.502 198.104 128 237.832v52.78c-217.102 17.748-384 124.42-384 253.388h397.306c-8.664-30.53-13.306-62.732-13.306-96z"
                className=""
              ></path>
              <path
                d="M736 448c-159.058 0-288 128.942-288 288s128.942 288 288 288c159.056 0 288-128.942 288-288s-128.942-288-288-288zM896 768h-128v128h-64v-128h-128v-64h128v-128h64v128h128v64z"
                className=""
              ></path>
            </svg>
            <span className="sidebar-text button">{props.text}</span>
          </div>
        </Link>
      </div>
      <div className="sidebar-container2">
        <Link to="/edit-profile" className="sidebar-navlink1">
          <div className="sidebar-container3">
            <svg viewBox="0 0 1024 1024" className="sidebar-icon3">
              <path
                d="M884 300l-78 78-160-160 78-78q12-12 30-12t30 12l100 100q12 12 12 30t-12 30zM128 736l472-472 160 160-472 472h-160v-160z"
                className=""
              ></path>
            </svg>
            <span className="sidebar-text1 button">{props.text1}</span>
          </div>
        </Link>
      </div>
      <Link to="/my-project" className="sidebar-navlink2">
        <div className="sidebar-container4">
          <div className="sidebar-container5">
            <svg
              viewBox="0 0 1073.7371428571428 1024"
              className="sidebar-icon5"
            >
              <path
                d="M1073.714 544c0 13.714-8.571 27.429-17.714 37.714l-192 226.286c-33.143 38.857-100.571 69.714-150.857 69.714h-621.714c-20.571 0-49.714-6.286-49.714-32 0-13.714 8.571-27.429 17.714-37.714l192-226.286c33.143-38.857 100.571-69.714 150.857-69.714h621.714c20.571 0 49.714 6.286 49.714 32zM877.714 347.429v91.429h-475.429c-71.429 0-160 40.571-206.286 95.429l-195.429 229.714c0-4.571-0.571-9.714-0.571-14.286v-548.571c0-70.286 57.714-128 128-128h182.857c70.286 0 128 57.714 128 128v18.286h310.857c70.286 0 128 57.714 128 128z"
                className=""
              ></path>
            </svg>
            <span className="sidebar-text2 button">{props.text3}</span>
          </div>
        </div>
      </Link>
      <div className="sidebar-container6">
        <div className="sidebar-container7">
          <div className="sidebar-container8">
            <svg viewBox="0 0 1024 1024" className="sidebar-icon7">
              <path
                d="M384 853.333h-170.667c-11.776 0-22.4-4.736-30.165-12.501s-12.501-18.389-12.501-30.165v-597.333c0-11.776 4.736-22.4 12.501-30.165s18.389-12.501 30.165-12.501h170.667c23.552 0 42.667-19.115 42.667-42.667s-19.115-42.667-42.667-42.667h-170.667c-35.328 0-67.413 14.379-90.496 37.504s-37.504 55.168-37.504 90.496v597.333c0 35.328 14.379 67.413 37.504 90.496s55.168 37.504 90.496 37.504h170.667c23.552 0 42.667-19.115 42.667-42.667s-19.115-42.667-42.667-42.667zM793.003 469.333h-409.003c-23.552 0-42.667 19.115-42.667 42.667s19.115 42.667 42.667 42.667h409.003l-140.501 140.501c-16.683 16.683-16.683 43.691 0 60.331s43.691 16.683 60.331 0l213.333-213.333c4.096-4.096 7.168-8.789 9.259-13.824 6.4-15.445 3.328-33.92-9.259-46.507l-213.333-213.333c-16.683-16.683-43.691-16.683-60.331 0s-16.683 43.691 0 60.331z"
                className=""
              ></path>
            </svg>
          </div>
          <span className="sidebar-text3 button">{props.text4}</span>
        </div>
      </div>
    </div>
  )
}

Sidebar.defaultProps = {
  text2: 'Security',
  text4: 'Logout',
  rootClassName: '',
  text1: 'Edit Profile',
  text3: 'My Projects',
  text: 'Profile Page',
}

Sidebar.propTypes = {
  text2: PropTypes.string,
  text4: PropTypes.string,
  rootClassName: PropTypes.string,
  text1: PropTypes.string,
  text3: PropTypes.string,
  text: PropTypes.string,
}

export default Sidebar
