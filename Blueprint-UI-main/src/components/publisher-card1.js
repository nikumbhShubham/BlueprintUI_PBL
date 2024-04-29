import React from 'react'

import PropTypes from 'prop-types'

import './publisher-card1.css'

const PublisherCard1 = (props) => {
  return (
    <div className={`publisher-card1-container ${props.rootClassName} `}>
      <div className="publisher-card1-container1">
        <div className="publisher-card1-feature-card">
          <img
            alt={props.imageAlt1}
            src={props.imageSrc1}
            className="publisher-card1-image"
          />
          <div className="publisher-card1-feature-card1">
            <h2 className="publisher-card1-text">Springboot</h2>
            <button type="button" className="publisher-card1-button button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card1-feature-card2">
          <img
            alt={props.imageAlt12}
            src={props.imageSrc12}
            className="publisher-card1-image1"
          />
          <div className="publisher-card1-feature-card3">
            <h2 className="publisher-card1-text1">Bootstrap</h2>
            <button type="button" className="publisher-card1-button1 button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card1-feature-card4">
          <img
            alt={props.imageAlt2}
            src={props.imageSrc2}
            className="publisher-card1-image2"
          />
          <div className="publisher-card1-feature-card5">
            <h2 className="publisher-card1-text2">Bootstrap</h2>
            <button type="button" className="publisher-card1-button2 button">
              Visit
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

PublisherCard1.defaultProps = {
  imageSrc12: '/icons1-200h.jpg',
  imageAlt2: 'image',
  rootClassName: '',
  imageAlt1: 'image',
  imageSrc1: '/springboot-200h.png',
  imageSrc2: '/flutter-200h.png',
  imageAlt12: 'image',
}

PublisherCard1.propTypes = {
  imageSrc12: PropTypes.string,
  imageAlt2: PropTypes.string,
  rootClassName: PropTypes.string,
  imageAlt1: PropTypes.string,
  imageSrc1: PropTypes.string,
  imageSrc2: PropTypes.string,
  imageAlt12: PropTypes.string,
}

export default PublisherCard1
