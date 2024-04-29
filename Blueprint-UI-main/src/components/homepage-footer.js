import React from 'react'

import PropTypes from 'prop-types'

import './homepage-footer.css'

const HomepageFooter = (props) => {
  return (
    <div
      id="support"
      className={`homepage-footer-container ${props.rootClassName} `}
    >
      <div className="homepage-footer-container01">
        <span className="homepage-footer-text">
          <span className="">Say hello and let&apos;s</span>
          <br className=""></br>
          <span className=""> work together !</span>
        </span>
        <div className="homepage-footer-container02">
          <div className="homepage-footer-container03">
            <div className="homepage-footer-container04">
              <svg
                viewBox="0 0 877.7142857142857 1024"
                className="homepage-footer-icon"
              >
                <path
                  d="M585.143 512c0-80.571-65.714-146.286-146.286-146.286s-146.286 65.714-146.286 146.286 65.714 146.286 146.286 146.286 146.286-65.714 146.286-146.286zM664 512c0 124.571-100.571 225.143-225.143 225.143s-225.143-100.571-225.143-225.143 100.571-225.143 225.143-225.143 225.143 100.571 225.143 225.143zM725.714 277.714c0 29.143-23.429 52.571-52.571 52.571s-52.571-23.429-52.571-52.571 23.429-52.571 52.571-52.571 52.571 23.429 52.571 52.571zM438.857 152c-64 0-201.143-5.143-258.857 17.714-20 8-34.857 17.714-50.286 33.143s-25.143 30.286-33.143 50.286c-22.857 57.714-17.714 194.857-17.714 258.857s-5.143 201.143 17.714 258.857c8 20 17.714 34.857 33.143 50.286s30.286 25.143 50.286 33.143c57.714 22.857 194.857 17.714 258.857 17.714s201.143 5.143 258.857-17.714c20-8 34.857-17.714 50.286-33.143s25.143-30.286 33.143-50.286c22.857-57.714 17.714-194.857 17.714-258.857s5.143-201.143-17.714-258.857c-8-20-17.714-34.857-33.143-50.286s-30.286-25.143-50.286-33.143c-57.714-22.857-194.857-17.714-258.857-17.714zM877.714 512c0 60.571 0.571 120.571-2.857 181.143-3.429 70.286-19.429 132.571-70.857 184s-113.714 67.429-184 70.857c-60.571 3.429-120.571 2.857-181.143 2.857s-120.571 0.571-181.143-2.857c-70.286-3.429-132.571-19.429-184-70.857s-67.429-113.714-70.857-184c-3.429-60.571-2.857-120.571-2.857-181.143s-0.571-120.571 2.857-181.143c3.429-70.286 19.429-132.571 70.857-184s113.714-67.429 184-70.857c60.571-3.429 120.571-2.857 181.143-2.857s120.571-0.571 181.143 2.857c70.286 3.429 132.571 19.429 184 70.857s67.429 113.714 70.857 184c3.429 60.571 2.857 120.571 2.857 181.143z"
                  className=""
                ></path>
              </svg>
              <svg
                viewBox="0 0 877.7142857142857 1024"
                className="homepage-footer-icon2"
              >
                <path
                  d="M135.429 808h132v-396.571h-132v396.571zM276 289.143c-0.571-38.857-28.571-68.571-73.714-68.571s-74.857 29.714-74.857 68.571c0 37.714 28.571 68.571 73.143 68.571h0.571c46.286 0 74.857-30.857 74.857-68.571zM610.286 808h132v-227.429c0-121.714-65.143-178.286-152-178.286-70.857 0-102.286 39.429-119.429 66.857h1.143v-57.714h-132s1.714 37.143 0 396.571v0h132v-221.714c0-11.429 0.571-23.429 4-32 9.714-23.429 31.429-48 68-48 47.429 0 66.286 36 66.286 89.714v212zM877.714 237.714v548.571c0 90.857-73.714 164.571-164.571 164.571h-548.571c-90.857 0-164.571-73.714-164.571-164.571v-548.571c0-90.857 73.714-164.571 164.571-164.571h548.571c90.857 0 164.571 73.714 164.571 164.571z"
                  className=""
                ></path>
              </svg>
              <svg viewBox="0 0 1024 1024" className="homepage-footer-icon4">
                <path
                  d="M854 342v-86l-342 214-342-214v86l342 212zM854 170q34 0 59 26t25 60v512q0 34-25 60t-59 26h-684q-34 0-59-26t-25-60v-512q0-34 25-60t59-26h684z"
                  className=""
                ></path>
              </svg>
              <svg
                viewBox="0 0 877.7142857142857 1024"
                className="homepage-footer-icon6"
              >
                <path
                  d="M731.429 348.571c-21.714 9.714-44.571 16-69.143 19.429 25.143-14.857 44-38.857 53.143-66.857-23.429 13.714-49.143 24-76.571 29.143-21.714-23.429-53.143-37.714-87.429-37.714-66.286 0-120 53.714-120 120 0 9.143 0.571 18.857 2.857 27.429-100-5.143-188.571-52.571-248-125.714-10.286 17.714-16.571 38.857-16.571 60.571 0 41.714 19.429 78.286 52 100-20-0.571-38.857-6.286-57.143-14.857v1.143c0 58.286 44 106.857 98.857 117.714-10.286 2.857-18.286 4.571-29.143 4.571-7.429 0-14.857-1.143-22.286-2.286 15.429 47.429 59.429 82.286 112 83.429-41.143 32-92.571 51.429-149.143 51.429-9.714 0-19.429-0.571-28.571-1.714 53.143 33.714 116 53.714 184 53.714 220.571 0 341.714-182.857 341.714-341.714 0-5.143 0-10.286-0.571-15.429 23.429-16.571 44-37.714 60-62.286zM877.714 237.714v548.571c0 90.857-73.714 164.571-164.571 164.571h-548.571c-90.857 0-164.571-73.714-164.571-164.571v-548.571c0-90.857 73.714-164.571 164.571-164.571h548.571c90.857 0 164.571 73.714 164.571 164.571z"
                  className=""
                ></path>
              </svg>
            </div>
          </div>
        </div>
        <span className="homepage-footer-text4">{props.text}</span>
      </div>
      <div className="homepage-footer-container05">
        <div className="homepage-footer-container06">
          <span className="homepage-footer-text5">{props.text12}</span>
          <input
            type="text"
            placeholder="Your email address"
            className="homepage-footer-textinput input"
          />
        </div>
        <div className="homepage-footer-container07">
          <div className="homepage-footer-container08"></div>
          <span className="homepage-footer-text6">{props.text122}</span>
          <input
            type="text"
            placeholder="Describe your project"
            className="homepage-footer-textinput1 input"
          />
        </div>
        <button type="button" className="homepage-footer-button button">
          {props.button}
        </button>
        <div className="homepage-footer-container09"></div>
      </div>
    </div>
  )
}

HomepageFooter.defaultProps = {
  text122: 'Input your message',
  textinputPlaceholder1112: 'placeholder',
  text2: 'Text',
  textinputPlaceholder: 'placeholder',
  textinputPlaceholder11: 'placeholder',
  text121: 'Text',
  button: 'Submit',
  textinputPlaceholder1: 'placeholder',
  textinputPlaceholder1111: 'placeholder',
  text1: 'Email',
  rootClassName: '',
  text11: 'Text',
  text: '© 2024 BlueprintUI , Inc. • Privacy • Terms  • SitemapText',
  text12: 'Email',
  textinputPlaceholder111: 'placeholder',
}

HomepageFooter.propTypes = {
  text122: PropTypes.string,
  textinputPlaceholder1112: PropTypes.string,
  text2: PropTypes.string,
  textinputPlaceholder: PropTypes.string,
  textinputPlaceholder11: PropTypes.string,
  text121: PropTypes.string,
  button: PropTypes.string,
  textinputPlaceholder1: PropTypes.string,
  textinputPlaceholder1111: PropTypes.string,
  text1: PropTypes.string,
  rootClassName: PropTypes.string,
  text11: PropTypes.string,
  text: PropTypes.string,
  text12: PropTypes.string,
  textinputPlaceholder111: PropTypes.string,
}

export default HomepageFooter
