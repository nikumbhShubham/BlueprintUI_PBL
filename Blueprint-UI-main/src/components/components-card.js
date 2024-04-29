import React from 'react'

import PropTypes from 'prop-types'

import './components-card.css'

const ComponentsCard = (props) => {
  return (
    <div className={`components-card-container ${props.rootClassName} `}>
      <div className="components-card-feature-card">
        <img
          alt={props.imageAlt}
          src={props.imageSrc}
          className="components-card-image"
        />
        <div className="components-card-container1">
          <h2 className="components-card-text">Component Name</h2>
          <span className="components-card-text1">
            <span className="">500+ items sold</span>
            <br className=""></br>
            <span className="">30 items left</span>
            <br className=""></br>
          </span>
        </div>
      </div>
    </div>
  )
}

ComponentsCard.defaultProps = {
  rootClassName: '',
  imageAlt: 'image',
  imageSrc: '/header-300h.jpg',
}

ComponentsCard.propTypes = {
  rootClassName: PropTypes.string,
  imageAlt: PropTypes.string,
  imageSrc: PropTypes.string,
}

export default ComponentsCard
