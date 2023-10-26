package com.djx.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * 登录相关的控制器
 *
 * @author qiudw
 * @date 7/11/2023
 */
@Controller
@RequestMapping
public class LoginController {

    /**
     * 跳转到登录页面
     *
     * @return 登录页面的地址
     */
    @GetMapping("/login")
    public ModelAndView loginPage() {
        return new ModelAndView("login");
    }

    /**
     * 首页
     *
     * @return 首页路径
     */
    @GetMapping({"/", "/index"})
    public ModelAndView index() {
        return new ModelAndView("index");
    }

}
