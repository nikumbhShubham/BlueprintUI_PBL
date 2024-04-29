import React from 'react'
import { Link } from 'react-router-dom'

import PropTypes from 'prop-types'

import './workspace-sidebar.css'

const WorkspaceSidebar = (props) => {
  return (
    <div className={`workspace-sidebar-sidebar ${props.rootClassName} `}>
      <Link to="/" className="workspace-sidebar-navlink">
        {props.text5}
      </Link>
      <Link to="/component" className="workspace-sidebar-navlink1">
        {props.text6}
      </Link>
      <Link to="/ui-packages" className="workspace-sidebar-navlink2">
        {props.text7}
      </Link>
      <Link to="/my-project" className="workspace-sidebar-navlink3">
        {props.text8}
      </Link>
      <div className="workspace-sidebar-profile">
        <svg viewBox="0 0 1024 1024" className="workspace-sidebar-icon">
          <path
            d="M870.286 765.143c-14.857-106.857-58.286-201.714-155.429-214.857-50.286 54.857-122.857 89.714-202.857 89.714s-152.571-34.857-202.857-89.714c-97.143 13.143-140.571 108-155.429 214.857 79.429 112 210.286 185.714 358.286 185.714s278.857-73.714 358.286-185.714zM731.429 365.714c0-121.143-98.286-219.429-219.429-219.429s-219.429 98.286-219.429 219.429 98.286 219.429 219.429 219.429 219.429-98.286 219.429-219.429zM1024 512c0 281.714-228.571 512-512 512-282.857 0-512-229.714-512-512 0-282.857 229.143-512 512-512s512 229.143 512 512z"
            className=""
          ></path>
        </svg>
        <div className="workspace-sidebar-container">
          <span className="workspace-sidebar-text">John Doe</span>
          <span className="workspace-sidebar-text1">View Profile</span>
        </div>
      </div>
    </div>
  )
}

WorkspaceSidebar.defaultProps = {
  text6: 'Components',
  text3: 'My Projects',
  rootClassName: '',
  text1: 'Edit Profile',
  text4: 'Logout',
  text: 'Profile Page',
  text5: 'Home',
  text7: 'UI packages',
  text2: 'Security',
  text8: 'My projects',
}

WorkspaceSidebar.propTypes = {
  text6: PropTypes.string,
  text3: PropTypes.string,
  rootClassName: PropTypes.string,
  text1: PropTypes.string,
  text4: PropTypes.string,
  text: PropTypes.string,
  text5: PropTypes.string,
  text7: PropTypes.string,
  text2: PropTypes.string,
  text8: PropTypes.string,
}

export default WorkspaceSidebar
