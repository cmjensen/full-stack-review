import React from 'react'
import { Switch, Route } from 'react-router-dom'
import  Auth from './components/Auth'
import Main from './components/Main'

export default (
    <Switch>
        <Route exact path='/' component={ Auth }/>
        <Route path='/main' component={ Main }/>
    </Switch>
)