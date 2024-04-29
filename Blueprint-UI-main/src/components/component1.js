import React from 'react'

import PropTypes from 'prop-types'

import './component1.css'

const Component1 = (props) => {
  return (
    <div className={`component1-container ${props.rootClassName} `}>
      <img
        alt={props.imageAlt}
        src={props.imageSrc}
        className="component1-image"
      />
    </div>
  )
}

Component1.defaultProps = {
  imageSrc: '/user-200h.png',
  rootClassName: '',
  imageAlt: 'image',
}

Component1.propTypes = {
  imageSrc: PropTypes.string,
  rootClassName: PropTypes.string,
  imageAlt: PropTypes.string,
}

export default Component1
