import React from 'react'

import PropTypes from 'prop-types'

import AllPublishersCard from './all-publishers-card'
import './publishers.css'

const Publishers = (props) => {
  return (
    <div className={`publishers-container ${props.rootClassName} `}>
      <span className="publishers-text">{props.text}</span>
      <span className="publishers-text1">{props.text1}</span>
      <div className="publishers-container1"></div>
      <div className="publishers-container2"></div>
      <AllPublishersCard rootClassName="all-publishers-card-root-class-name"></AllPublishersCard>
      <div className="publishers-container3"></div>
    </div>
  )
}

Publishers.defaultProps = {
  imageAlt: 'image',
  text2: 'Link',
  linkText: 'https://example.com',
  button1: 'Button',
  imageSrc: 'f23700a5-41bf-4205-be9a-d9f2b0c77098',
  button: 'visit',
  rootClassName: '',
  text1:
    'Carbon offers exclusive advertising access on 600+ hand-picked websites and apps in the design, development, and tech spaces. The network is segmented by audience so you can run targeted campaigns at scale. Some of our network members include:',
  text: 'Meet a few of our amazing publishers',
}

Publishers.propTypes = {
  imageAlt: PropTypes.string,
  text2: PropTypes.string,
  linkText: PropTypes.string,
  button1: PropTypes.string,
  imageSrc: PropTypes.string,
  button: PropTypes.string,
  rootClassName: PropTypes.string,
  text1: PropTypes.string,
  text: PropTypes.string,
}

export default Publishers
