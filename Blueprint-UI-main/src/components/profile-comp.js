import React from 'react'
import { Link } from 'react-router-dom'

import PropTypes from 'prop-types'

import './profile-comp.css'

const ProfileComp = (props) => {
  return (
    <div className={`profile-comp-container ${props.rootClassName} `}>
      <h1 className="profile-comp-text">{props.heading}</h1>
      <div className="profile-comp-container01">
        <div className="profile-comp-container02">
          <div className="profile-comp-container03">
            <div className="profile-comp-container04">
              <div className="profile-comp-container05">
                <span className="profile-comp-text01">{props.text11}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container06">
            <div className="profile-comp-container07">
              <div className="profile-comp-container08">
                <span className="profile-comp-text02">{props.text62}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container09">
            <div className="profile-comp-container10">
              <div className="profile-comp-container11">
                <span className="profile-comp-text03">{props.text612}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container12">
            <div className="profile-comp-container13">
              <div className="profile-comp-container14">
                <span className="profile-comp-text04">{props.text6112}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container15">
            <div className="profile-comp-container16">
              <div className="profile-comp-container17">
                <span className="profile-comp-text05">{props.text61112}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container18">
            <div className="profile-comp-container19">
              <div className="profile-comp-container20">
                <span className="profile-comp-text06">{props.text611112}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container21">
            <div className="profile-comp-container22">
              <div className="profile-comp-container23">
                <span className="profile-comp-text07">{props.text6111113}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container24">
            <div className="profile-comp-container25">
              <div className="profile-comp-container26">
                <span className="profile-comp-text08">
                  {props.text61111122}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="profile-comp-container27">
          <input
            type="text"
            placeholder="Your name"
            className="profile-comp-textinput input"
          />
          <input
            type="text"
            placeholder="Not provided"
            className="profile-comp-textinput01 input"
          />
          <input
            type="text"
            placeholder="You location"
            className="profile-comp-textinput02 input"
          />
          <input
            type="text"
            placeholder="Tell us about yourself(interets, experience, etc.)"
            className="profile-comp-textinput03 input"
          />
          <input
            type="text"
            placeholder="Your blog, portfolio, etc."
            className="profile-comp-textinput04 input"
          />
          <input
            type="text"
            placeholder="Your Github username or ur"
            className="profile-comp-textinput05 input"
          />
          <input
            type="text"
            placeholder="Your LinkedIn username or ur"
            className="profile-comp-textinput06 input"
          />
          <input
            type="text"
            placeholder="Your Twitter username or ur"
            className="profile-comp-textinput07 input"
          />
        </div>
        <div className="profile-comp-container28">
          <Link to="/edit-profile" className="profile-comp-navlink button">
            {props.button2}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink01 button">
            {props.button26}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink02 button">
            {props.button25}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink03 button">
            {props.button24}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink04 button">
            {props.button23}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink05 button">
            {props.button22}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink06 button">
            {props.button211}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink07 button">
            {props.button2112}
          </Link>
        </div>
      </div>
      <h1 className="profile-comp-text09">{props.heading2}</h1>
      <div className="profile-comp-container29">
        <div className="profile-comp-container30">
          <div className="profile-comp-container31">
            <div className="profile-comp-container32">
              <div className="profile-comp-container33">
                <span className="profile-comp-text10">{props.text111}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container34">
            <div className="profile-comp-container35">
              <div className="profile-comp-container36">
                <span className="profile-comp-text11">{props.text621}</span>
              </div>
            </div>
          </div>
          <div className="profile-comp-container37">
            <div className="profile-comp-container38">
              <div className="profile-comp-container39">
                <span className="profile-comp-text12">{props.text6121}</span>
              </div>
            </div>
          </div>
        </div>
        <div className="profile-comp-container40">
          <input
            type="text"
            placeholder="Add a workplace"
            className="profile-comp-textinput08 input"
          />
          <input
            type="text"
            placeholder="Add a school"
            className="profile-comp-textinput09 input"
          />
          <input
            type="text"
            placeholder="Add skills"
            className="profile-comp-textinput10 input"
          />
        </div>
        <div className="profile-comp-container41">
          <Link to="/edit-profile" className="profile-comp-navlink08 button">
            {props.button27}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink09 button">
            {props.button261}
          </Link>
          <Link to="/edit-profile" className="profile-comp-navlink10 button">
            {props.button251}
          </Link>
        </div>
      </div>
      <div className="profile-comp-container42">
        <div className="profile-comp-container43"></div>
      </div>
    </div>
  )
}

ProfileComp.defaultProps = {
  button2112: 'Edit',
  rootClassName: '',
  button1: 'Edit',
  textinputPlaceholder18: 'placeholder',
  text621: 'Education',
  text10: 'Name',
  text61111122: 'Twitter',
  button211: 'Edit',
  text6: 'Gender',
  button11111111: 'Edit',
  text11: 'Name',
  text12: 'Name',
  textinputPlaceholder16: 'placeholder',
  text6113: 'Summary',
  text61111: 'Github',
  textinputPlaceholder141: 'placeholder',
  text61: 'Location',
  button1111112111: 'Edit',
  text611111: 'LinkedIn',
  text6111111: 'Name',
  text7: 'Name',
  text4: 'Text',
  textinputPlaceholder12: 'placeholder',
  button212: 'Button',
  button111: 'Edit',
  button231: 'Button',
  button23: 'Edit',
  heading: 'Account',
  textinputPlaceholder1: 'placeholder',
  text61111121: 'Name',
  text6111113: 'LinkedIn',
  text6121: 'Skills',
  textinputPlaceholder111: 'placeholder',
  button2111: 'Button',
  textinputPlaceholder17: 'placeholder',
  text61121: 'Summary',
  text61113: 'Website',
  button22: 'Edit',
  text611111221: 'Twitter',
  text611111211: 'Name',
  button24: 'Edit',
  text6111114: 'LinkedIn',
  button251: 'Edit',
  text611112: 'Github',
  textinputPlaceholder13: 'placeholder',
  heading2: 'Experience',
  textinputPlaceholder11: 'placeholder',
  text1: 'Text',
  text6112: 'Summary',
  textinputPlaceholder151: 'placeholder',
  button261: 'Edit',
  text6111112111: 'Name',
  button221: 'Button',
  button1111111: 'Edit',
  text51: 'Text',
  text611: 'Summary',
  text61111123: 'Twitter',
  button241: 'Button',
  text613: 'Location',
  heading1: 'Heading',
  button1111: 'Edit',
  textinputPlaceholder121: 'placeholder',
  text61111111: 'Name',
  textinputPlaceholder: 'placeholder',
  button111111211: 'Edit',
  textinputPlaceholder131: 'placeholder',
  button2: 'Edit',
  text3: 'Text',
  text6111121: 'Github',
  text: 'Name',
  button111111: 'Edit',
  text611113: 'Github',
  button11111: 'Edit',
  text61111131: 'LinkedIn',
  text612: 'Location',
  textinputPlaceholder14: 'placeholder',
  button1111112: 'Edit',
  button11: 'Edit',
  text63: 'Gender',
  text2: 'Text',
  textinputPlaceholder161: 'placeholder',
  text61112: 'Website',
  button25: 'Edit',
  text611121: 'Website',
  text5: 'Text',
  text6111: 'Website',
  button27: 'Edit',
  button11111121: 'Edit',
  button26: 'Edit',
  button21: 'Button',
  text62: 'Gender',
  text8: 'Name',
  textinputPlaceholder171: 'placeholder',
  text111: 'Work',
  text6111112: 'Twitter',
  text9: 'Name',
  textinputPlaceholder15: 'placeholder',
  button: 'Edit',
}

ProfileComp.propTypes = {
  button2112: PropTypes.string,
  rootClassName: PropTypes.string,
  button1: PropTypes.string,
  textinputPlaceholder18: PropTypes.string,
  text621: PropTypes.string,
  text10: PropTypes.string,
  text61111122: PropTypes.string,
  button211: PropTypes.string,
  text6: PropTypes.string,
  button11111111: PropTypes.string,
  text11: PropTypes.string,
  text12: PropTypes.string,
  textinputPlaceholder16: PropTypes.string,
  text6113: PropTypes.string,
  text61111: PropTypes.string,
  textinputPlaceholder141: PropTypes.string,
  text61: PropTypes.string,
  button1111112111: PropTypes.string,
  text611111: PropTypes.string,
  text6111111: PropTypes.string,
  text7: PropTypes.string,
  text4: PropTypes.string,
  textinputPlaceholder12: PropTypes.string,
  button212: PropTypes.string,
  button111: PropTypes.string,
  button231: PropTypes.string,
  button23: PropTypes.string,
  heading: PropTypes.string,
  textinputPlaceholder1: PropTypes.string,
  text61111121: PropTypes.string,
  text6111113: PropTypes.string,
  text6121: PropTypes.string,
  textinputPlaceholder111: PropTypes.string,
  button2111: PropTypes.string,
  textinputPlaceholder17: PropTypes.string,
  text61121: PropTypes.string,
  text61113: PropTypes.string,
  button22: PropTypes.string,
  text611111221: PropTypes.string,
  text611111211: PropTypes.string,
  button24: PropTypes.string,
  text6111114: PropTypes.string,
  button251: PropTypes.string,
  text611112: PropTypes.string,
  textinputPlaceholder13: PropTypes.string,
  heading2: PropTypes.string,
  textinputPlaceholder11: PropTypes.string,
  text1: PropTypes.string,
  text6112: PropTypes.string,
  textinputPlaceholder151: PropTypes.string,
  button261: PropTypes.string,
  text6111112111: PropTypes.string,
  button221: PropTypes.string,
  button1111111: PropTypes.string,
  text51: PropTypes.string,
  text611: PropTypes.string,
  text61111123: PropTypes.string,
  button241: PropTypes.string,
  text613: PropTypes.string,
  heading1: PropTypes.string,
  button1111: PropTypes.string,
  textinputPlaceholder121: PropTypes.string,
  text61111111: PropTypes.string,
  textinputPlaceholder: PropTypes.string,
  button111111211: PropTypes.string,
  textinputPlaceholder131: PropTypes.string,
  button2: PropTypes.string,
  text3: PropTypes.string,
  text6111121: PropTypes.string,
  text: PropTypes.string,
  button111111: PropTypes.string,
  text611113: PropTypes.string,
  button11111: PropTypes.string,
  text61111131: PropTypes.string,
  text612: PropTypes.string,
  textinputPlaceholder14: PropTypes.string,
  button1111112: PropTypes.string,
  button11: PropTypes.string,
  text63: PropTypes.string,
  text2: PropTypes.string,
  textinputPlaceholder161: PropTypes.string,
  text61112: PropTypes.string,
  button25: PropTypes.string,
  text611121: PropTypes.string,
  text5: PropTypes.string,
  text6111: PropTypes.string,
  button27: PropTypes.string,
  button11111121: PropTypes.string,
  button26: PropTypes.string,
  button21: PropTypes.string,
  text62: PropTypes.string,
  text8: PropTypes.string,
  textinputPlaceholder171: PropTypes.string,
  text111: PropTypes.string,
  text6111112: PropTypes.string,
  text9: PropTypes.string,
  textinputPlaceholder15: PropTypes.string,
  button: PropTypes.string,
}

export default ProfileComp
