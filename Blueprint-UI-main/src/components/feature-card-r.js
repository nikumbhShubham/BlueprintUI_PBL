import React from 'react'

import PropTypes from 'prop-types'

import './feature-card-r.css'

const FeatureCardR = (props) => {
  return (
    <div className={`feature-card-r-feature-card ${props.rootClassName} `}>
      <svg viewBox="0 0 1024 1024" className="feature-card-r-icon">
        <path
          d="M928 128h-288c0-70.692-57.306-128-128-128-70.692 0-128 57.308-128 128h-288c-17.672 0-32 14.328-32 32v832c0 17.674 14.328 32 32 32h832c17.674 0 32-14.326 32-32v-832c0-17.672-14.326-32-32-32zM512 64c35.346 0 64 28.654 64 64s-28.654 64-64 64c-35.346 0-64-28.654-64-64s28.654-64 64-64zM896 960h-768v-768h128v96c0 17.672 14.328 32 32 32h448c17.674 0 32-14.328 32-32v-96h128v768z"
          className=""
        ></path>
        <path
          d="M448 858.51l-205.254-237.254 58.508-58.51 146.746 114.744 274.742-242.744 58.514 58.508z"
          className=""
        ></path>
      </svg>
      <h2 className="feature-card-r-text">{props.title}</h2>
      <span className="feature-card-r-text1">{props.description}</span>
    </div>
  )
}

FeatureCardR.defaultProps = {
  title: 'Lorem ipsum',
  action: 'SEE MORE',
  description: 'Lorem ipsum dolor sit amet, consectetur adipiscing.',
  rootClassName: '',
}

FeatureCardR.propTypes = {
  title: PropTypes.string,
  action: PropTypes.string,
  description: PropTypes.string,
  rootClassName: PropTypes.string,
}

export default FeatureCardR
