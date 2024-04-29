import React from 'react'

import PropTypes from 'prop-types'

import PublisherCard1 from './publisher-card1'
import PublisherCard2 from './publisher-card2'
import PublisherCard21 from './publisher-card21'
import './all-publishers-card.css'

const AllPublishersCard = (props) => {
  return (
    <div className={`all-publishers-card-container ${props.rootClassName} `}>
      <PublisherCard1
        rootClassName="publisher-card1-root-class-name"
        className=""
      ></PublisherCard1>
      <PublisherCard2
        rootClassName="publisher-card2-root-class-name"
        className=""
      ></PublisherCard2>
      <PublisherCard21
        rootClassName="publisher-card21-root-class-name"
        className=""
      ></PublisherCard21>
    </div>
  )
}

AllPublishersCard.defaultProps = {
  heading: 'Heading',
  imageAlt: 'image',
  rootClassName: '',
  text: 'Text',
  heading1: 'Heading',
  imageSrc: 'da2f79f3-a52d-48e2-a150-d31c384d372f',
}

AllPublishersCard.propTypes = {
  heading: PropTypes.string,
  imageAlt: PropTypes.string,
  rootClassName: PropTypes.string,
  text: PropTypes.string,
  heading1: PropTypes.string,
  imageSrc: PropTypes.string,
}

export default AllPublishersCard
