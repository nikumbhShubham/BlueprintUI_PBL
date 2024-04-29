import React from 'react'
import { Link } from 'react-router-dom'

import PropTypes from 'prop-types'

import './workspace-header.css'

const WorkspaceHeader = (props) => {
  return (
    <div className={`workspace-header-container ${props.rootClassName} `}>
      <span className="workspace-header-text">
        <span className="">&lt;BlueprintUI&gt;</span>
      </span>
      <div className="workspace-header-container1">
        <div className="workspace-header-container2">
          <div className="workspace-header-container3">
            <div className="workspace-header-container4">
              <div className="workspace-header-container5">
                <svg viewBox="0 0 1024 1024" className="workspace-header-icon">
                  <path
                    d="M406 598q80 0 136-56t56-136-56-136-136-56-136 56-56 136 56 136 136 56zM662 598l212 212-64 64-212-212v-34l-12-12q-76 66-180 66-116 0-197-80t-81-196 81-197 197-81 196 81 80 197q0 42-20 95t-46 85l12 12h34z"
                    className=""
                  ></path>
                </svg>
                <textarea
                  placeholder="Search"
                  className="workspace-header-textarea textarea"
                ></textarea>
              </div>
              <Link to="/workspace" className="workspace-header-navlink button">
                <svg viewBox="0 0 1024 1024" className="workspace-header-icon2">
                  <path
                    d="M810 554h-256v256h-84v-256h-256v-84h256v-256h84v256h256v84z"
                    className=""
                  ></path>
                </svg>
                <span className="workspace-header-text2">{props.text}</span>
              </Link>
            </div>
          </div>
          <svg viewBox="0 0 1024 1024" className="workspace-header-icon4">
            <path
              d="M521.143 969.143c0-5.143-4-9.143-9.143-9.143-45.143 0-82.286-37.143-82.286-82.286 0-5.143-4-9.143-9.143-9.143s-9.143 4-9.143 9.143c0 55.429 45.143 100.571 100.571 100.571 5.143 0 9.143-4 9.143-9.143zM987.429 804.571c0 40-33.143 73.143-73.143 73.143h-256c0 80.571-65.714 146.286-146.286 146.286s-146.286-65.714-146.286-146.286h-256c-40 0-73.143-33.143-73.143-73.143 84.571-71.429 182.857-199.429 182.857-475.429 0-109.714 90.857-229.714 242.286-252-2.857-6.857-4.571-14.286-4.571-22.286 0-30.286 24.571-54.857 54.857-54.857s54.857 24.571 54.857 54.857c0 8-1.714 15.429-4.571 22.286 151.429 22.286 242.286 142.286 242.286 252 0 276 98.286 404 182.857 475.429z"
              className=""
            ></path>
          </svg>
        </div>
        <Link to="/profile-page" className="workspace-header-navlink1">
          <svg viewBox="0 0 1024 1024" className="workspace-header-icon6">
            <path
              d="M870.286 765.143c-14.857-106.857-58.286-201.714-155.429-214.857-50.286 54.857-122.857 89.714-202.857 89.714s-152.571-34.857-202.857-89.714c-97.143 13.143-140.571 108-155.429 214.857 79.429 112 210.286 185.714 358.286 185.714s278.857-73.714 358.286-185.714zM731.429 365.714c0-121.143-98.286-219.429-219.429-219.429s-219.429 98.286-219.429 219.429 98.286 219.429 219.429 219.429 219.429-98.286 219.429-219.429zM1024 512c0 281.714-228.571 512-512 512-282.857 0-512-229.714-512-512 0-282.857 229.143-512 512-512s512 229.143 512 512z"
              className=""
            ></path>
          </svg>
        </Link>
      </div>
    </div>
  )
}

WorkspaceHeader.defaultProps = {
  text: 'Create new project',
  textareaPlaceholder: 'placeholder',
  textinputPlaceholder: 'placeholder',
  rootClassName: '',
  button: 'Create new project',
}

WorkspaceHeader.propTypes = {
  text: PropTypes.string,
  textareaPlaceholder: PropTypes.string,
  textinputPlaceholder: PropTypes.string,
  rootClassName: PropTypes.string,
  button: PropTypes.string,
}

export default WorkspaceHeader
