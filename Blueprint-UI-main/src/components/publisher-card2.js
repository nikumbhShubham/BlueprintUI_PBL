import React from 'react'

import PropTypes from 'prop-types'

import './publisher-card2.css'

const PublisherCard2 = (props) => {
  return (
    <div className={`publisher-card2-container ${props.rootClassName} `}>
      <div className="publisher-card2-container1">
        <div className="publisher-card2-feature-card">
          <img
            alt={props.imageAlt1}
            src={props.imageSrc1}
            className="publisher-card2-image"
          />
          <div className="publisher-card2-feature-card1">
            <h2 className="publisher-card2-text">Angular</h2>
            <button type="button" className="publisher-card2-button button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card2-feature-card2">
          <img
            alt={props.imageAlt12}
            src={props.imageSrc12}
            className="publisher-card2-image1"
          />
          <div className="publisher-card2-feature-card3">
            <h2 className="publisher-card2-text1">Vue</h2>
            <button type="button" className="publisher-card2-button1 button">
              Visit
            </button>
          </div>
        </div>
        <div className="publisher-card2-feature-card4">
          <img
            alt={props.imageAlt2}
            src={props.imageSrc2}
            className="publisher-card2-image2"
          />
          <div className="publisher-card2-feature-card5">
            <h2 className="publisher-card2-text2">React</h2>
            <button type="button" className="publisher-card2-button2 button">
              Visit
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

PublisherCard2.defaultProps = {
  imageAlt2: 'image',
  imageSrc12: '/vue-200h.png',
  imageAlt: 'image',
  imageAlt12: 'image',
  imageSrc1: '/angular-200h.png',
  rootClassName: '',
  imageSrc: '929c4db6-afd1-4843-81ee-9f2880a390f1',
  imageAlt1: 'image',
  imageSrc2: '/react-200h.png',
}

PublisherCard2.propTypes = {
  imageAlt2: PropTypes.string,
  imageSrc12: PropTypes.string,
  imageAlt: PropTypes.string,
  imageAlt12: PropTypes.string,
  imageSrc1: PropTypes.string,
  rootClassName: PropTypes.string,
  imageSrc: PropTypes.string,
  imageAlt1: PropTypes.string,
  imageSrc2: PropTypes.string,
}

export default PublisherCard2
