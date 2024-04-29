import React from 'react'

import PropTypes from 'prop-types'

import './header-of-all-publishers.css'

const HeaderOfAllPublishers = (props) => {
  return (
    <div
      className={`header-of-all-publishers-container ${props.rootClassName} `}
    >
      <h1 className="header-of-all-publishers-text">{props.heading}</h1>
      <span className="header-of-all-publishers-text1">{props.text}</span>
    </div>
  )
}

HeaderOfAllPublishers.defaultProps = {
  heading: 'Meet a few of our amazing publishers.',
  text: 'Carbon offers exclusive advertising access on 600+ hand-picked websites and apps in the design, development, and tech spaces. The network is segmented by audience so you can run targeted campaigns at scale. Some of our network members include:',
  rootClassName: '',
}

HeaderOfAllPublishers.propTypes = {
  heading: PropTypes.string,
  text: PropTypes.string,
  rootClassName: PropTypes.string,
}

export default HeaderOfAllPublishers
