import React from 'react'

import PropTypes from 'prop-types'

import './profile-edit-comp.css'

const ProfileEditComp = (props) => {
  return (
    <div className={`profile-edit-comp-container ${props.rootClassName} `}>
      <h1 className="profile-edit-comp-text">{props.heading}</h1>
      <div className="profile-edit-comp-container1">
        <input
          type="text"
          placeholder="Old password"
          className="profile-edit-comp-textinput input"
        />
        <input
          type="text"
          placeholder="New password"
          className="profile-edit-comp-textinput1 input"
        />
        <input
          type="text"
          placeholder="Confirm new password"
          className="profile-edit-comp-textinput2 input"
        />
        <button
          type="button"
          className="profile-edit-comp-update-password button"
        >
          {props.button}
        </button>
        <div className="profile-edit-comp-container2">
          <a
            href={props.linkText}
            target="_blank"
            rel="noreferrer noopener"
            className="profile-edit-comp-link"
          >
            {props.text}
          </a>
        </div>
      </div>
    </div>
  )
}

ProfileEditComp.defaultProps = {
  rootClassName: '',
  linkText: 'https://example.com',
  heading: 'Change Password',
  button: 'Update password',
  text: 'I forgot my password',
}

ProfileEditComp.propTypes = {
  rootClassName: PropTypes.string,
  linkText: PropTypes.string,
  heading: PropTypes.string,
  button: PropTypes.string,
  text: PropTypes.string,
}

export default ProfileEditComp
