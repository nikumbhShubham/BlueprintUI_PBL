import React from 'react'

import PropTypes from 'prop-types'

import './publisher-card21.css'

const PublisherCard21 = (props) => {
  return (
    <div className={`publisher-card21-container ${props.rootClassName} `}>
      <div className="publisher-card21-container1">
        <div className="publisher-card21-feature-card">
          <img
            alt={props.imageAlt1}
            src={props.imageSrc1}
            className="publisher-card21-image"
          />
          <div className="publisher-card21-feature-card1">
            <h2 className="publisher-card21-text">Tailwind</h2>
            <button type="button" className="publisher-card21-button button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card21-feature-card2">
          <img
            alt={props.imageAlt12}
            src={props.imageSrc12}
            className="publisher-card21-image1"
          />
          <div className="publisher-card21-feature-card3">
            <h2 className="publisher-card21-text1">Ionic</h2>
            <button type="button" className="publisher-card21-button1 button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card21-feature-card4">
          <img
            alt={props.imageAlt2}
            src={props.imageSrc2}
            className="publisher-card21-image2"
          />
          <div className="publisher-card21-feature-card5">
            <h2 className="publisher-card21-text2">Html</h2>
            <button type="button" className="publisher-card21-button2 button">
              Visit
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

PublisherCard21.defaultProps = {
  imageSrc1: '/tailwind-200h.jpg',
  imageAlt2: 'image',
  imageSrc2: '/html-200h.png',
  imageSrc12: '/ionic-200h.png',
  imageAlt1: 'image',
  imageAlt12: 'image',
  rootClassName: '',
}

PublisherCard21.propTypes = {
  imageSrc1: PropTypes.string,
  imageAlt2: PropTypes.string,
  imageSrc2: PropTypes.string,
  imageSrc12: PropTypes.string,
  imageAlt1: PropTypes.string,
  imageAlt12: PropTypes.string,
  rootClassName: PropTypes.string,
}

export default PublisherCard21
